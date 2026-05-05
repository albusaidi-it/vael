# Architecture

## How It Works in Plain English

You give VAEL a software name and version. It runs four investigation stages in sequence, each one building on the last:

```
You type:  software="log4j"  version="2.14.1"
                    │
    ┌───────────────▼───────────────┐
    │  Stage 1 — Find the CVEs      │  Asks 3 vulnerability databases at once:
    │                               │  NVD (US government) · OSV (Google) · GHSA (GitHub)
    │  Removes duplicates           │
    │  Checks your version          │  → Flags only the CVEs that affect *your* version
    └───────────────┬───────────────┘
                    │
    ┌───────────────▼───────────────┐
    │  Stage 2 — Score each CVE     │  Asks 3 live intelligence sources:
    │                               │  EPSS (attack probability) · CISA KEV (active attacks)
    │  Assigns a priority tier      │  VulnCheck (hacker group attribution)
    │  PATCH NOW / HIGH / MONITOR   │
    │  / DEFER                      │
    └───────────────┬───────────────┘
                    │
    ┌───────────────▼───────────────┐
    │  Stage 3 — Hunt for exploits  │  Searches 12 sources for working attack code:
    │                               │  GitHub · Exploit-DB · Metasploit · Packet Storm
    │  Grades each exploit found    │  Nuclei · Gitee · Seebug · CNVD · Naver · Yandex
    │  Checks version compatibility │  Baidu + CNVD (Chinese/Korean/Russian platforms)
    └───────────────┬───────────────┘
                    │
    ┌───────────────▼───────────────┐
    │  Stage 4 — Exposure check     │  Scans the internet to count how many servers
    │                               │  running this software are publicly reachable
    │  (Requires Shodan/Censys key) │  Shodan · Censys
    └───────────────┬───────────────┘
                    │
    ┌───────────────▼───────────────┐
    │  Verdict — AI risk decision   │  Gemini AI (or built-in rule engine as fallback)
    │                               │
    │  🚨 PATCH NOW                 │  Reads all evidence from stages 1–4 and
    │  ⚠️  HIGH                     │  produces a single verdict with:
    │  👁️  MONITOR                  │  - Plain-English recommendation
    │  📋 DEFER                     │  - Confidence percentage
    └───────────────────────────────┘  - Key evidence list
```

All stages run as fast as possible — each source within a stage is queried at the same time (in parallel), so the full pipeline typically completes in under 30 seconds.

---

## Example: Log4Shell (CVE-2021-44228)

This is what a real VAEL run looks like for one of the most severe CVEs ever discovered:

```
Input: log4j  version 2.14.1
│
├─ Stage 1 — CVE Discovery
│   ├─ NVD:   CVSS score 10.0 (maximum), CRITICAL severity, affects version 2.14.1 ✓
│   ├─ OSV:   version 2.14.1 is in the affected range [2.0-beta9, 2.15.0)
│   └─ GHSA:  same CVE confirmed, fixed version is 2.15.0
│
├─ Stage 2 — Exploitability Scoring
│   ├─ EPSS:  97.5% probability of exploitation — top 0.1% of all CVEs ever
│   ├─ KEV:   YES — confirmed exploited in the wild since December 10, 2021
│   ├─ Threat intel: used by APT41 (Chinese state hackers), Conti ransomware, LockBit ransomware
│   └─ Priority tier: PATCH NOW (score: 100/100)
│
├─ Stage 3 — Exploit Hunt
│   ├─ GitHub:       14 public repositories, best one has 14,000 stars — WEAPONIZED
│   ├─ Exploit-DB:   3 entries
│   ├─ Nuclei:       1 detection template (CVE-2021-44228.yaml)
│   ├─ Metasploit:   full exploit module ready to run
│   ├─ Packet Storm: 2 advisories
│   └─ Naver (🇰🇷):  2 GitHub links discovered via Korean search
│
├─ Stage 4 — Internet Exposure
│   ├─ Shodan:  ~850,000 servers publicly exposed on the internet
│   └─ Censys:  confirms wide exposure
│
└─ Verdict
    ├─ Label:      🚨 PATCH NOW
    ├─ Confidence: 99%
    └─ Evidence:   Active exploitation confirmed (KEV) · EPSS 97.5% · 14 GitHub PoCs
                   Metasploit module available · Used by APT41, Conti, LockBit
                   850,000 exposed servers
```

---

## Key Design Decisions

> The sections below are technical. They explain *why* VAEL is built the way it is. Skip to the [next page](03-installation.md) if you just want to get started.

### Everything runs in parallel

Within each stage, all sources are queried at the same time — not one after another. Stage 1 queries NVD, OSV, and GHSA simultaneously. Stage 3 runs up to 7 exploit-hunting searches per CVE at once. This is why the full pipeline finishes in ~30 seconds even when querying dozens of sources.

### Stage 3 can upgrade Stage 2 results

If Stage 3 finds a Metasploit module for a CVE that Stage 2 had rated as "no known exploit," Stage 2's assessment is updated before the verdict is generated. The AI always sees the most complete picture.

### Results are cached locally

Every API response is saved in a local SQLite database (`feeds/vael_cache.db`). Running VAEL twice on the same software within 24 hours uses the saved data instead of making new API calls — faster, and preserves your API rate limits. Cache lifetimes vary by source: EPSS and NVD are refreshed every 24 hours, CISA KEV every 6 hours.

### Rate limit awareness

VAEL tracks how many API requests it has made to each source and warns you if you are approaching a limit. These warnings appear in the dashboard and in API responses. You will never hit a rate limit silently.

### Smart name matching

If you type `log4j-core` VAEL knows you mean `log4j`. If you type `MobileIron` it knows you mean `ivanti-epmm`. It uses a combination of exact matching, version-stripping, and fuzzy text matching to normalize software names before querying, so typos and aliases still return useful results.

### The AI never makes up data

When Gemini produces the final verdict, it receives a structured document of facts that VAEL already collected. It is explicitly told not to search the internet or invent data. Its job is to reason over the evidence and write a clear explanation — nothing more. If Gemini is unavailable, a built-in rule engine produces the same output format.

---

## Module Map (for developers)

```
core/
├── cve_mapper.py          Stage 1 orchestrator
│   ├── nvd_fetcher.py     NVD API v2 (paginated, CPE search)
│   ├── osv_fetcher.py     OSV.dev (batch POST by package)
│   ├── ghsa_fetcher.py    GitHub GraphQL (securityVulnerabilities)
│   ├── misconfig_mapper.py CWE + CIS local knowledge base
│   ├── name_resolver.py   Fuzzy canonical name resolution
│   └── version_utils.py   semver + CPE version range matching
│
├── exploit_eval.py        Stage 2 orchestrator
│   ├── epss_fetcher.py    FIRST.org EPSS bulk CSV
│   ├── kev_fetcher.py     CISA KEV JSON feed
│   ├── vulncheck_fetcher.py VulnCheck community API
│   ├── patch_detector.py  Fixed version extraction
│   └── exploit_scorer.py  VEP scoring algorithm
│
├── poc_harvester.py       Stage 3 orchestrator
│   ├── github_harvester.py   GitHub Search API + README analysis
│   ├── exploitdb_harvester.py Exploit-DB CSV + live API
│   ├── nuclei_harvester.py   Nuclei template index
│   ├── metasploit_harvester.py rapid7/metasploit-framework search
│   ├── packet_storm_harvester.py packetstormsecurity.com scraping
│   └── intl_harvester.py  Gitee · Seebug · CNVD · Naver · Yandex · Baidu
│
├── exposure_checker.py    Stage 4 (Shodan + Censys)
├── ai_reasoner.py         Gemini + deterministic fallback
├── delta_tracker.py       Baseline snapshots + diff engine
├── sbom_parser.py         CycloneDX / SPDX / requirements.txt
├── rate_limiter.py        Central API budget tracker
└── cache.py               SQLite WAL cache with zlib compression
```

---

## Data Schemas (for developers)

Every stage output is a Pydantic v2 model serializable to JSON:

| Schema | Key fields |
|--------|-----------|
| `Stage1Result` | `cves: list[CVERecord]`, `misconfig_flags`, `sources_queried`, `rate_limit_warnings` |
| `CVERecord` | `cve_id`, `cvss_v3`, `cwes`, `version_matched`, `affected_versions_raw` |
| `Stage2Result` | `enrichments: list[ExploitabilityEnrichment]`, `kev_count`, `t0_patch_now_count` |
| `ExploitabilityEnrichment` | `cve_id`, `epss`, `in_kev`, `vep_score`, `vep_tier`, `exploit_maturity`, `threat_intel` |
| `Stage3Result` | `bundles: list[CVEPoCBundle]`, `total_pocs`, `weaponized_count` |
| `PoCRecord` | `cve_id`, `source`, `url`, `quality`, `version_compatibility`, `stars`, `raw_meta` |
| `Stage4Result` | `exposures: list[ExposureResult]`, `peak_level` |
| `RiskVerdict` | `label`, `confidence`, `recommendation`, `reasoning_summary`, `key_evidence`, `used_ai` |
| `DeltaReport` | `changes: list[CVEDelta]`, `has_critical_changes` |
