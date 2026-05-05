# Data Sources

Every source VAEL queries, what it provides, its cache TTL, and its rate limits.

---

## Stage 1 — CVE Discovery

### NVD (National Vulnerability Database)

| Property | Value |
|----------|-------|
| **URL** | https://nvd.nist.gov/developers/vulnerabilities |
| **Auth** | Optional API key (`NVD_API_KEY`) |
| **Rate limit (no key)** | 5 requests / 30 seconds |
| **Rate limit (with key)** | 50 requests / 30 seconds |
| **Cache TTL** | 24 hours |
| **What it provides** | CVE ID, CVSS v3/v2 scores, CWEs, CPE strings, description, published/modified dates, affected version ranges |

NIST's authoritative CVE database. VAEL queries the v2 API with CPE-based filtering for the target software. Results are paginated; VAEL fetches up to `MAX_NVD_RESULTS` (default: 200).

---

### OSV (Open Source Vulnerabilities)

| Property | Value |
|----------|-------|
| **URL** | https://api.osv.dev/v1/query |
| **Auth** | None required |
| **Rate limit** | None published; effectively unlimited |
| **Cache TTL** | 24 hours |
| **What it provides** | CVE ID, ecosystem-specific package name, affected version ranges, severity, references |

OSV aggregates vulnerability data for open-source packages across ecosystems: PyPI, npm, Maven, Go, Rust, Ruby, NuGet, and more. The batch POST endpoint accepts a `{package: {name, ecosystem}}` query. VAEL auto-detects the ecosystem from the software name when not specified.

---

### GHSA (GitHub Security Advisories)

| Property | Value |
|----------|-------|
| **URL** | https://api.github.com/graphql |
| **Auth** | Optional GitHub token (`GITHUB_TOKEN`) |
| **Rate limit (no token)** | 10 requests / minute |
| **Rate limit (with token)** | 5,000 requests / hour |
| **Cache TTL** | 24 hours |
| **What it provides** | CVE ID, GHSA ID, severity, affected package/ecosystem, first_patched version, CVSS score |

GitHub's security advisory database, queried via the GraphQL `securityVulnerabilities` endpoint. Often has first-patched version information that NVD lacks.

---

## Stage 2 — Exploitability

### EPSS (Exploit Prediction Scoring System)

| Property | Value |
|----------|-------|
| **URL** | https://api.first.org/data/v1/epss |
| **Auth** | None |
| **Rate limit** | None published |
| **Cache TTL** | 24 hours |
| **What it provides** | `epss` (0–1 probability), `percentile` (0–1 rank among all CVEs) |

Published by FIRST.org. The EPSS score is the probability that a CVE will be exploited in the wild within the next 30 days. VAEL downloads the full bulk CSV daily and looks up scores locally — no per-CVE API calls needed.

---

### CISA KEV (Known Exploited Vulnerabilities)

| Property | Value |
|----------|-------|
| **URL** | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json |
| **Auth** | None |
| **Rate limit** | None |
| **Cache TTL** | 6 hours |
| **What it provides** | Confirmed active exploitation flag, date added, due date for federal agencies |

CISA's authoritative list of CVEs confirmed as exploited in the wild. A KEV match is the strongest possible signal that a vulnerability needs immediate attention. VAEL downloads the full catalog (a single JSON file) and does local lookups.

---

### VulnCheck

| Property | Value |
|----------|-------|
| **URL** | https://api.vulncheck.com/v3/index/ |
| **Auth** | Required (`VULNCHECK_API_KEY`) |
| **Rate limit** | Depends on plan |
| **Cache TTL** | 24 hours |
| **What it provides** | APT group names, ransomware campaign names, initial access indicator |

VulnCheck's community API provides threat actor attribution: which APT groups and ransomware families have been observed using a specific CVE. VAEL queries two endpoints: `initial-access` (APT groups) and `ransomware` (ransomware families). Without this key, threat intel fields are empty but the pipeline completes.

---

## Stage 3 — PoC Harvesting

### GitHub

| Property | Value |
|----------|-------|
| **URL** | https://api.github.com/search/repositories |
| **Auth** | Optional (`GITHUB_TOKEN`) |
| **Rate limit (no token)** | 10 requests / minute |
| **Rate limit (with token)** | 30 requests / minute (code search) |
| **Cache TTL** | 6 hours |
| **What it provides** | Repository URLs, star counts, description, topics, README content, author |

VAEL searches GitHub for repositories mentioning the CVE ID. Quality is classified by: star count thresholds, presence of keywords like "exploit", "shell", "rce", "payload" in the README, and topic tags. High-starred repositories with executable code keywords are classified as WEAPONIZED.

---

### Exploit-DB

| Property | Value |
|----------|-------|
| **URL** | https://www.exploit-db.com |
| **Auth** | None |
| **Rate limit** | Best-effort (no published limit) |
| **Cache TTL** | 24 hours |
| **What it provides** | Exploit title, type, platform, author, URL, CVE association |

The original exploit database maintained by Offensive Security. VAEL queries the CSV download and the live search API. Remote exploits are classified as WEAPONIZED; local exploits as FUNCTIONAL.

---

### Nuclei Templates

| Property | Value |
|----------|-------|
| **URL** | https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/ |
| **Auth** | None |
| **Rate limit** | GitHub raw content CDN |
| **Cache TTL** | 24 hours |
| **What it provides** | Template YAML path, CVE ID, severity, description |

Nuclei is a fast vulnerability scanner. Its template library contains YAML definitions for thousands of CVEs. A Nuclei template is evidence of a reliably detectable (often exploitable) vulnerability — classified as WEAPONIZED.

---

### Metasploit Framework

| Property | Value |
|----------|-------|
| **URL** | https://api.github.com/search/code (rapid7/metasploit-framework) |
| **Auth** | Optional (`GITHUB_TOKEN`) |
| **Rate limit** | Shared with GitHub PoC search |
| **Cache TTL** | 24 hours |
| **What it provides** | Module `.rb` file path, module name, CVE association |

VAEL searches the official Metasploit Framework repository for `.rb` modules under `modules/` that reference the CVE ID. A Metasploit module is the strongest exploitability signal: ready-to-use weaponized exploit. All Metasploit results are classified as WEAPONIZED.

---

### Packet Storm

| Property | Value |
|----------|-------|
| **URL** | https://packetstormsecurity.com/search/?q={cve_id} |
| **Auth** | None |
| **Rate limit** | Best-effort scraping |
| **Cache TTL** | 24 hours |
| **What it provides** | Advisory/exploit title, URL, publication date |

Packet Storm Security is a long-running archive of security advisories, exploits, and tools. VAEL scrapes the search results page using BeautifulSoup. Classification is based on title keywords.

---

### Gitee (China)

| Property | Value |
|----------|-------|
| **URL** | https://gitee.com/api/v5/repos/search |
| **Auth** | None |
| **Rate limit** | Unknown; limited accessibility from outside China |
| **Cache TTL** | 12 hours |
| **Notes** | SSL verification disabled (`verify=False`) due to certificate issues |

Gitee is China's primary Git hosting platform, widely used by Chinese security researchers who publish PoC code. Accessible from outside China, though the search API may return limited results.

---

### Seebug (China)

| Property | Value |
|----------|-------|
| **URL** | https://www.seebug.org |
| **Auth** | None |
| **Rate limit** | Best-effort |
| **Cache TTL** | 12 hours |
| **What it provides** | Vulnerability title, CVE association, severity, PoC availability indicator |

Seebug is a Chinese vulnerability database with a large catalog of PoC exploits. VAEL scrapes the search results. Results are filtered to those referencing the queried CVE ID.

---

### CNVD (China National Vulnerability Database)

| Property | Value |
|----------|-------|
| **URL** | https://www.cnvd.org.cn |
| **Auth** | None |
| **Rate limit** | Best-effort |
| **Cache TTL** | 12 hours |
| **What it provides** | Chinese government vulnerability entries with CVE cross-references |

The official Chinese government vulnerability database. More reliably accessible than Seebug from outside China, and often has entries for CVEs that don't appear on Western platforms.

---

### Naver (Korea)

| Property | Value |
|----------|-------|
| **URL** | https://search.naver.com/search.naver |
| **Auth** | None |
| **Rate limit** | Best-effort |
| **Cache TTL** | 6 hours |
| **Query language** | Korean: `취약점 익스플로잇 PoC {CVE_ID}` |

South Korea's largest search engine. Korean security researchers publish vulnerability write-ups and PoCs on Korean platforms that don't appear in Google. Naver results reliably include GitHub links to Korean-authored PoC repositories.

---

### Yandex (Russia)

| Property | Value |
|----------|-------|
| **URL** | https://yandex.ru/search/ |
| **Auth** | None |
| **Rate limit** | Blocked by CAPTCHA from server/datacenter IPs |
| **Cache TTL** | 6 hours |
| **Query language** | Russian: `уязвимость эксплойт PoC {CVE_ID}` |

Russia's dominant search engine. Russian security researchers publish extensively in Russian-language communities. **Note:** Yandex immediately redirects to a CAPTCHA page from datacenter IP ranges. Results will be empty unless running from a residential IP.

---

### Baidu (China)

| Property | Value |
|----------|-------|
| **URL** | https://www.baidu.com/s |
| **Auth** | None |
| **Rate limit** | Returns JS-rendered content not parseable without headless browser |
| **Cache TTL** | 6 hours |
| **Query language** | Chinese: `漏洞利用 概念验证 exploit {CVE_ID}` |

China's dominant search engine. **Note:** Baidu's search results page is fully JavaScript-rendered. VAEL's HTTP-based scraping returns an HTML shell with no content. Results will always be empty without a headless browser. CNVD is the recommended alternative for Chinese language results.

---

## Stage 4 — Internet Exposure

### Shodan

| Property | Value |
|----------|-------|
| **URL** | https://api.shodan.io |
| **Auth** | Required (`SHODAN_API_KEY`) |
| **Rate limit** | 1 query credit per search |
| **Cache TTL** | 24 hours |
| **What it provides** | Exposed host count, top countries, top ports, banner samples |

Shodan continuously scans the internet and indexes service banners. VAEL queries it with a crafted search string for the software name. Free accounts have limited credits.

---

### Censys

| Property | Value |
|----------|-------|
| **URL** | https://search.censys.io/api |
| **Auth** | Required (`CENSYS_API_ID` + `CENSYS_API_SECRET`) |
| **Rate limit** | 250 queries / month (free tier) |
| **Cache TTL** | 24 hours |
| **What it provides** | Cross-validated exposed host count, certificate data, service fingerprints |

Censys provides independent verification of Shodan's exposure findings. Free tier has 250 monthly queries, which is sufficient for low-volume security teams.

---

## AI Verdict

### Google Gemini

| Property | Value |
|----------|-------|
| **Model** | `gemini-2.5-flash` (configurable via `GEMINI_MODEL`) |
| **Auth** | Required (`GEMINI_API_KEY`) |
| **Rate limit** | Depends on plan; generous free tier |
| **What it provides** | Structured verdict with label, confidence, recommendation, reasoning, key evidence |

Gemini receives a fully pre-fetched JSON document containing all upstream findings. It reasons over the data but cannot search the internet or fabricate CVE information. If unavailable, the deterministic fallback produces the same output format.
