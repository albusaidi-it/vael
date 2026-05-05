# Usage

## Web UI

Start the server and open `http://localhost:8000` in your browser:

```bash
uvicorn api.main:app --reload
```

Results appear progressively as each stage completes — you do not have to wait for everything to finish. CVE data starts appearing within a few seconds while the exploit hunt continues in the background.

### What each section shows

| Section | What you'll see |
|---------|----------------|
| **Stage 1 — CVE Discovery** | Total CVEs found, how many are CRITICAL or HIGH severity, how many are confirmed to affect your specific version |
| **Stage 2 — Exploitability** | Priority rating per CVE, attack probability (EPSS), whether it's on the government's active-exploitation list (KEV), and any hacker groups known to use it |
| **Stage 3 — Exploit Hunt** | Any working attack code found, how dangerous it is, which sources found it, and whether it targets your version |
| **International Results** | Attack code found specifically on Chinese (Gitee, Seebug, CNVD), Korean (Naver), or Russian (Yandex) platforms |
| **AI Verdict** | The final decision — PATCH NOW / HIGH / MONITOR / DEFER — with confidence score and plain-English reasoning |
| **Rate Limit Warnings** | Alert banner if any data source is running low on API request budget |
| **🇴🇲 Oman Internet Exposure** | Always-visible section below the main results — see below |

---

## Oman Internet Exposure

The **🇴🇲 Oman Internet Exposure** section sits below the main pipeline results and is always visible — you do not need to run an analysis first.

It searches Shodan, FOFA, Censys, and ZoomEye for publicly reachable hosts **inside Oman** that are running the target software or are exposed to specific CVEs.

### How to use it

1. Enter a software name (e.g. `apache`) and version (e.g. `2.4.50`) in the two input boxes.
2. Click **Search Oman 🇴🇲**.
3. Alternatively, run the main pipeline first and click **Copy from analysis** — this pre-fills the software and version from the form above.

### What the results mean

| Result | What it shows |
|--------|--------------|
| **CVE-matched hosts** | Hosts in Oman where the vulnerability CVE ID was found (keyword match). High confidence — these hosts likely have the software and the specific vulnerability indexed. |
| **Software exposure** | Hosts in Oman running the product by name (any version). Broader count — useful when CVE-level data is not available. |
| **Unique IPs sampled** | Deduplicated IPs across all sources in the sample pulled (up to 50 per source). |
| **Exposed hosts by city** | Geographic breakdown: Muscat, Sohar, Salalah, etc. |
| **Open ports distribution** | Most common ports found open (80, 443, 8080, 22, etc.) |
| **Sample host table** | Up to 50 individual IPs with port, protocol, city, and organization. |

### CVE-based search (automatic)

When you click Search, the tool automatically fetches the top CVEs for the software from NVD (instant if you have already run the main pipeline; one quick API call otherwise). It then queries all three sources using those CVE IDs rather than just a software name — this gives more targeted results.

The blue banner at the top of the results shows exactly which CVEs were searched and whether they came from your main analysis or were auto-fetched.

### Diagnostics

Each source card has a collapsible **▸ Diagnostics** section. If you get 0 results, expand it to see:

- The exact query sent to the API
- HTTP status codes
- Number of matches returned
- Any error messages or hints

### Source coverage

| Source | CVE search | Product search | Free tier |
|--------|-----------|---------------|-----------|
| **Shodan** | Keyword: `"CVE-xxxx" country:OM` | `product:"name" country:OM` | ✓ (product counts reliable; `vuln:` filter needs paid plan) |
| **FOFA** | `"CVE-xxxx" && country="OM"` | `app="name" && country="OM"` | ✓ (limited monthly queries) |
| **Censys** | `services.software.vulnerabilities.id` filter | `services.software.product` filter | ✓ (250 queries/month) |
| **ZoomEye** | `"CVE-xxxx" country:"Oman"` | `app:"name" country:"Oman"` | ✓ (10k results/month) |

**Why you might see 0 CVE-matched hosts but non-zero software exposure:**
Shodan's precise vulnerability indexing (`vuln:` filter) requires a paid plan. On free tier, CVE searches fall back to keyword matching, which only finds hosts whose banners literally contain the CVE ID — rare in practice. The product-name search is reliable on all plans.

---

## CLI

Run VAEL from the command line:

```bash
python cli/vael.py analyze --software <name> --version <version> [options]
```

### Examples

```bash
# Just find CVEs (Stage 1 only — fast, no network beyond CVE databases)
python cli/vael.py analyze --software log4j --version 2.14.1

# CVEs + exploitability scoring (Stages 1 and 2)
python cli/vael.py analyze --software log4j --version 2.14.1 --stage 2

# Full analysis with AI verdict (Stages 1, 2, 3 + verdict)
python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3 --verdict

# Output as JSON (for scripts and integrations)
python cli/vael.py analyze --software nginx --version 1.20.0 --stage 3 --verdict --json

# Use only saved/cached data — no internet required
python cli/vael.py analyze --software django --version 3.2.0 --offline

# Tell VAEL which package ecosystem to search (improves results for libraries)
python cli/vael.py analyze --software requests --version 2.28.0 --ecosystem PyPI

# Skip the US government CVE database (faster if you only need OSV/GitHub data)
python cli/vael.py analyze --software apache --version 2.4.50 --skip-nvd

# Use the built-in rule engine instead of Gemini AI for the verdict
python cli/vael.py analyze --software openssl --version 1.1.1 --stage 3 --verdict --deterministic
```

### All options

| Flag | Default | What it does |
|------|---------|-------------|
| `--software` / `-s` | required | Software name to analyze |
| `--version` / `-v` | required | Version number |
| `--stage` | `1` | How deep to run: 1 = CVEs only, 2 = + scoring, 3 = + exploit hunt |
| `--verdict` | off | Add the final AI verdict (needs `--stage 2` or higher) |
| `--ecosystem` / `-e` | auto-detect | Package ecosystem: PyPI, Maven, npm, Go, Rust, etc. |
| `--top-n` | `5` | How many top-priority CVEs to search for exploits |
| `--json` | off | Output raw JSON instead of the formatted table view |
| `--offline` | off | Use only locally saved data — make no network requests |
| `--skip-nvd` | off | Skip the US government NVD database |
| `--skip-osv` | off | Skip Google's OSV database |
| `--skip-github` | off | Skip GitHub exploit search |
| `--deterministic` | off | Use rule-based verdict instead of Gemini AI |
| `--max` | `100` | Maximum CVEs to fetch per data source |
| `--verbose` | off | Print detailed debug logs |
| `--nvd-key` | from env | NVD API key (or set `NVD_API_KEY` in `.env`) |
| `--github-token` | from env | GitHub token (or set `GITHUB_TOKEN` in `.env`) |
| `--gemini-key` | from env | Gemini AI key (or set `GEMINI_API_KEY` in `.env`) |

---

## REST API

Base URL: `http://localhost:8000`

Interactive documentation with a built-in test interface is available at `http://localhost:8000/docs`.

### Main endpoints

#### `GET /analyze/stream` — Live streaming results
The endpoint used by the web dashboard. Results stream to your browser in real time as each stage finishes.

```bash
curl -N "http://localhost:8000/analyze/stream?software=log4j&version=2.14.1"
```

You will receive a sequence of events: `stage1` → `stage2` → `stage3` → `verdict` → `done`.

#### `POST /analyze/full` — Full pipeline, single response
Runs all stages and returns everything in one JSON response (waits for completion before responding).

```bash
curl -X POST http://localhost:8000/analyze/full \
  -H "Content-Type: application/json" \
  -d '{"software": "log4j", "version": "2.14.1"}'
```

#### Partial runs

| Endpoint | What it runs |
|----------|-------------|
| `POST /analyze` | Stage 1 only (CVE list) |
| `POST /analyze/exploit` | Stages 1 + 2 (CVEs + exploitability scores) |
| `POST /analyze/pocs` | Stages 1 + 2 + 3 (full exploit hunt, no exposure check) |

### SBOM analysis — scan a whole project at once

An **SBOM** (Software Bill of Materials) is a file that lists all the libraries and dependencies in a project. VAEL can analyze an entire SBOM file and run the full pipeline on every component.

Supported formats: CycloneDX JSON, SPDX JSON, and `requirements.txt`.

```bash
curl -X POST http://localhost:8000/analyze/sbom \
  -F "file=@sbom.json"
```

### Delta tracking — what changed since last time?

```bash
curl -X POST http://localhost:8000/analyze/delta \
  -H "Content-Type: application/json" \
  -d '{"software": "log4j", "version": "2.14.1"}'
```

Compares today's results against the last saved snapshot for the same software and version. Returns a diff: new CVEs discovered, CVEs that moved to a higher priority tier, EPSS score changes, and new exploit code found.

### Oman Internet Exposure

```bash
POST /analyze/oman
```

Searches Shodan, FOFA, and Censys for publicly reachable hosts in Oman. Requires at least one of: `SHODAN_API_KEY`, `FOFA_API_KEY + FOFA_EMAIL`, or `CENSYS_API_ID + CENSYS_API_SECRET`.

```bash
curl -X POST http://localhost:8000/analyze/oman \
  -H "Content-Type: application/json" \
  -d '{"software": "apache", "version": "2.4.50"}'
```

Supply `cve_ids` to skip the automatic CVE lookup and use your own list:

```bash
curl -X POST http://localhost:8000/analyze/oman \
  -H "Content-Type: application/json" \
  -d '{"software": "apache", "version": "2.4.50", "cve_ids": ["CVE-2021-41773", "CVE-2021-42013"]}'
```

The response includes:
- `total_exposed` — total host count across all sources
- `cve_hits` — per-CVE exposure counts (Shodan / FOFA / Censys)
- `source_results` — full details per source including sample hosts, query used, and debug info
- `cve_ids_searched` — which CVEs were actually queried
- `cve_source` — `"auto_nvd"` (fetched automatically) or `"user_provided"`

### Internet exposure check

```bash
POST /analyze/exposure
```

Runs Stage 4 (Shodan + Censys) to estimate how many publicly-visible servers are running the software globally. Requires at least one exposure API key.

### Utility endpoints

```bash
GET /rate-limits     # How many API requests you have left for each data source
GET /health          # Is the server running? Which features are enabled?
GET /docs            # Interactive API documentation
```

### Demo endpoints — no internet required

```bash
GET /demo/log4shell       # Pre-built results for log4j 2.14.1 (Log4Shell)
GET /demo/spring4shell    # Pre-built results for Spring Framework 5.3.17
```

---

## Understanding the Results

### Priority tiers (Stage 2)

Stage 2 assigns each CVE an internal priority tier based on its attack probability, presence on the government's exploitation list, and exploit maturity. These tiers drive the final verdict.

| Internal tier | Plain meaning | What typically triggers it |
|--------------|--------------|---------------------------|
| `T0_PATCH_NOW` | This CVE needs immediate action | On the CISA KEV list, or attack probability > 50%, or a weaponized exploit exists |
| `T1_HIGH` | Fix within days | Attack probability > 10%, or functional exploit code is public |
| `T2_MONITOR` | Fix on your normal schedule | Attack probability > 1%, or only a write-up exists with no working code |
| `T3_DEFER` | Low priority | Attack probability < 1%, no known exploit anywhere |

### Exploit code quality (Stage 3)

When VAEL finds exploit code, it grades how dangerous it is:

| Grade | What it means | Example |
|-------|--------------|---------|
| **WEAPONIZED** | A finished, ready-to-run attack tool. Anyone can use it with minimal technical skill. | A Metasploit module, a Nuclei scanner template, or a GitHub repo with thousands of stars |
| **FUNCTIONAL** | Working code that proves the vulnerability is exploitable, but needs adaptation to use in a real attack. | A GitHub repo with a working demo video and the CVE ID in the name |
| **CONCEPTUAL** | A technical write-up or partial code that explains *how* the vulnerability works, but isn't a finished attack. | A blog post with pseudocode, or a repository with no working demo |
| **FAKE** | Appears to be exploit code but has been flagged as fake, a honeypot, or star-count-manipulated. | Repositories that suddenly gained thousands of fake stars |
| **UNKNOWN** | VAEL found something but couldn't determine how dangerous it is from the available information. | |

### Version compatibility

Each exploit is also checked against your specific version:

| Label | Meaning |
|-------|---------|
| **CONFIRMED** | The exploit explicitly states it works against your exact version |
| **LIKELY** | The exploit targets a version range that includes your version |
| **UNLIKELY** | The exploit targets a different version |
| **UNKNOWN** | No version information was available |

### Final verdict labels

These are the four possible outputs from the final verdict stage. Each is a concrete instruction.

| Label | Plain meaning | What to do |
|-------|--------------|-----------|
| 🚨 `PATCH NOW` | Fix this today. Active exploitation confirmed or a ready-to-use attack is public. | Patch immediately, even outside your maintenance window. Escalate if patching is blocked. |
| ⚠️ `HIGH` | Fix within days. No confirmed attacks yet, but working exploit code is already public. | Schedule an emergency change. Do not wait for the next sprint. |
| 👁️ `MONITOR` | Fix on your normal schedule, but keep watching. No working exploit yet. | Patch in routine maintenance. Re-run VAEL in 2–4 weeks — status can change. |
| 📋 `DEFER` | Low priority. No public exploit, very low attack probability. | Patch in your next routine maintenance cycle. |

> **Why not just use the CVSS score?**
> CVSS measures how severe a vulnerability *would be* if exploited. VAEL's verdict measures *how likely it is to actually be exploited, and how soon*. A CVSS 9.8 with no public exploit and 0.001% attack probability is often `DEFER`. A CVSS 6.5 already on the government's confirmed-exploitation list is always `PATCH NOW`.
