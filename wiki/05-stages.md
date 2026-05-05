# Pipeline Stages

## Stage 1 — CVE Discovery

**Orchestrator:** `core/cve_mapper.py`

Stage 1 takes `(software, version)` and returns a deduplicated, version-filtered list of CVE records.

### What it does

1. **Name resolution** — `core/name_resolver.py` canonicalizes the software name through a 4-layer pipeline:
   - Exact match against a YAML alias table (e.g., `MobileIron` → `ivanti-epmm`)
   - Strip-version heuristic (`log4j-core` → `log4j`)
   - Fuzzy match via `rapidfuzz` token_set_ratio at 78% threshold
   - Fallback: use raw input unchanged

2. **Parallel source queries** — Three databases are queried simultaneously:
   - **NVD** (`nvd_fetcher.py`) — NIST National Vulnerability Database, paginated, CPE-based search
   - **OSV** (`osv_fetcher.py`) — Open Source Vulnerabilities, batch POST by package/ecosystem
   - **GHSA** (`ghsa_fetcher.py`) — GitHub Security Advisories, via GraphQL API

3. **Deduplication** — Records from all three sources are merged by CVE ID. The source with the richest data wins for duplicate CVEs.

4. **Version matching** — Each CVE is checked against the input version using `core/version_utils.py`, which handles semver ranges and CPE version matching. `version_matched: true` means the CVE explicitly covers your version.

5. **CWE/CIS mapping** — `core/misconfig_mapper.py` checks CWEs against a local knowledge base and generates misconfiguration flags (e.g., "CWE-787 commonly indicates buffer overflow in memory-unsafe components").

### Output

`Stage1Result` with:
- `cves: list[CVERecord]` — sorted by CVSS score descending
- `total_cves`, `critical_count`, `high_count`, `version_matched_count`
- `misconfig_flags: list[MisconfigFlag]` — CWE/CIS knowledge base hits
- `sources_queried: list[str]`
- `rate_limit_warnings: list[str]`

---

## Stage 2 — Exploitability Evaluation

**Orchestrator:** `core/exploit_eval.py`

Stage 2 takes the Stage 1 CVE list and enriches each CVE with real-time exploitability signals.

### What it does

1. **Parallel enrichment** — Three sources are queried concurrently per CVE:
   - **EPSS** (`epss_fetcher.py`) — FIRST.org Exploit Prediction Scoring System. Returns a probability (0–1) that the CVE will be exploited in the wild within 30 days, and a percentile rank. Downloaded as a bulk CSV once per day.
   - **CISA KEV** (`kev_fetcher.py`) — Known Exploited Vulnerabilities catalog. A KEV match means this CVE is confirmed as actively exploited in the wild. Cache TTL: 6 hours.
   - **VulnCheck** (`vulncheck_fetcher.py`) — Community API providing APT group and ransomware campaign attribution. Returns lists like `apt_groups: ["APT41"]` and `ransomware_families: ["Conti", "LockBit"]`.

2. **Patch detection** — `core/patch_detector.py` extracts fixed version information from CVE descriptions and advisories.

3. **VEP scoring** — `core/exploit_scorer.py` computes a 0–100 Vulnerability Exploitation Probability score for each CVE:
   - EPSS contributes up to 40 points
   - KEV presence adds 30 points (auto-escalates to T0)
   - CVSS score contributes up to 20 points
   - Exploit maturity signal contributes up to 10 points

4. **Tier assignment** — Each CVE is assigned one of four tiers based on the VEP score. These tiers feed directly into the final verdict label (`PATCH NOW` / `HIGH` / `MONITOR` / `DEFER`):

   | Tier | VEP score threshold | Override condition | Maps to verdict |
   |------|--------------------|--------------------|----------------|
   | `T0_PATCH_NOW` | ≥ 70 | KEV present (any score) | `PATCH NOW` |
   | `T1_HIGH` | ≥ 40 | — | `HIGH` |
   | `T2_MONITOR` | ≥ 15 | — | `MONITOR` |
   | `T3_DEFER` | < 15 | — | `DEFER` |

   The final verdict is the highest tier found across all CVEs for the queried software. Stage 3 PoC evidence can upgrade a CVE's tier (e.g., `T2_MONITOR` → `T0_PATCH_NOW` if a Metasploit module is found).

### Output

`Stage2Result` with:
- `enrichments: list[ExploitabilityEnrichment]` — one per CVE, sorted by VEP score
- `top_priority_cves()` — method returning CVE + enrichment pairs
- `kev_count`, `t0_patch_now_count`, `t1_high_count`, `high_epss_count`

### Stage 2 is mutated by Stage 3

After Stage 3 harvests PoC evidence, it upgrades the `exploit_maturity` field on Stage 2 enrichments. If Metasploit has a module for a CVE that Stage 2 classified as `UNPROVEN`, the enrichment is updated to `WEAPONIZED` before the AI verdict runs. This means the verdict always reflects the best available evidence.

---

## Stage 3 — PoC Harvesting

**Orchestrator:** `core/poc_harvester.py`

Stage 3 searches for actual exploit code for the top-N CVEs from Stage 2.

### What it does

For each CVE in the priority list, up to 7 harvesters run in parallel:

#### Standard Sources

| Harvester | Source | What it finds |
|-----------|--------|---------------|
| `github_harvester.py` | GitHub Search API | Repositories with CVE ID in name/description/README; analyzes star count, topics, README content to classify quality |
| `exploitdb_harvester.py` | Exploit-DB CSV + API | Official exploit database entries; WEAPONIZED if marked as remote exploit |
| `nuclei_harvester.py` | projectdiscovery/nuclei-templates | Detection templates that prove exploitability |
| `metasploit_harvester.py` | rapid7/metasploit-framework | Module `.rb` files under `modules/`; all are WEAPONIZED |
| `packet_storm_harvester.py` | packetstormsecurity.com | Exploit advisories and PoC code; classified by title keywords |

#### International Sources

`intl_harvester.py` runs 6 search engines in parallel with native-language security queries:

| Engine | Language | Query terms | Notes |
|--------|----------|-------------|-------|
| Gitee | Chinese | CVE ID | China's GitHub alternative; SSL issues from outside China |
| Seebug | Chinese | CVE ID | Chinese vulnerability database with PoC entries |
| CNVD | Chinese | CVE ID | China National Vulnerability Database (government) |
| Naver | Korean | `취약점 익스플로잇 PoC {CVE}` | Korean search engine; returns useful results |
| Yandex | Russian | `уязвимость эксплойт PoC {CVE}` | Blocks non-residential IPs with CAPTCHA |
| Baidu | Chinese | `漏洞利用 概念验证 exploit {CVE}` | JS-rendered, not parseable without headless browser |

International results carry `raw_meta.discovered_via` so the UI can display them in a separate section.

### Quality Classification

| Quality | Criteria |
|---------|---------|
| `WEAPONIZED` | Metasploit module, Nuclei template, or GitHub repo with shellcode/RCE keywords + high stars |
| `FUNCTIONAL` | GitHub repo with working PoC indicators (demo video, CVE in name, moderate stars) |
| `CONCEPTUAL` | Discusses the vulnerability but requires significant work to use |
| `FAKE` | Star count manipulation detected, or explicitly marked as fake |

### Version Compatibility

Each PoC is checked against the queried version using README content analysis and metadata:
- `CONFIRMED` — explicitly states it targets this version
- `LIKELY` — targets a version range that includes this version
- `UNLIKELY` — targets a different version
- `UNKNOWN` — no version information available

### Output

`Stage3Result` with:
- `bundles: list[CVEPoCBundle]` — one bundle per harvested CVE
- `total_pocs`, `weaponized_count`, `cves_with_compatible_pocs`
- Each `CVEPoCBundle` contains `pocs: list[PoCRecord]`, `best_quality`, `compatible_pocs_count`

---

## Stage 4 — Internet Exposure

**Orchestrator:** `core/exposure_checker.py`

Stage 4 estimates how many internet-facing hosts run the vulnerable software. Requires at least one exposure API key.

### What it does

Two services are queried in parallel:

- **Shodan** — Queries the Shodan API with a crafted search query for the software name. Returns banner-confirmed host counts, top countries, and port distribution.
- **Censys** — Cross-references Shodan findings using the Censys certificates and services index.

Results are combined into an `ExposureResult` per software with:
- `total_exposed` — estimated internet-facing host count
- `top_countries` — top 5 countries by host count
- `top_ports` — most common ports
- `confidence` — HIGH / MEDIUM / LOW based on data quality

### Output

`Stage4Result` with:
- `exposures: list[ExposureResult]`
- `peak_level` — highest exposure level found

---

## AI Verdict

**Module:** `core/ai_reasoner.py`

The final stage synthesizes all upstream data into a single risk decision.

### How it works

A structured JSON document is assembled containing the complete output of Stages 1–4. This document is sent to Gemini with a prompt that:

1. Explains what each field means
2. Explicitly forbids the model from searching the internet or inventing data
3. Requires output in a specific JSON schema

The model produces:
- `label`: PATCH NOW / HIGH / MONITOR / DEFER
- `confidence`: 0–1 float
- `recommendation`: one-sentence action
- `reasoning_summary`: paragraph explaining the decision
- `key_evidence`: list of the most important signals

### Deterministic Fallback

If Gemini is unavailable (no API key, quota exceeded, or network error), a rule-based engine in the same module produces the same output format:

- Any T0 CVE → PATCH NOW (confidence: 0.95)
- Any T1 CVE with PoC → HIGH (confidence: 0.90)
- Any T1 CVE → HIGH (confidence: 0.85)
- Any T2 CVE with WEAPONIZED PoC → HIGH (confidence: 0.80)
- Any T2 CVE → MONITOR (confidence: 0.75)
- Otherwise → DEFER (confidence: 0.70)

The `used_ai` field in the response indicates which path was taken.
