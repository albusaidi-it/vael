# Changelog

All notable changes to VAEL are documented in this file.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

---

## [0.4.0] — 2026-04-29

### Added

- **AttackerKB integration (Stage 1)** — Rapid7's community exploitability database is now a fifth parallel CVE source. Each topic carries a community attacker score and exploitation status that enriches the Stage 1 record set. Requires `ATTACKERKB_API_KEY` (free tier available); gracefully skipped when not configured.
- **Pastebin harvester (Stage 3)** — Searches `pastebin.com` for public pastes referencing each CVE ID. Results are classified by exploit-keyword heuristics (FUNCTIONAL / CONCEPTUAL). No API key required.
- **ZoomEye exposure source (Oman Intel)** — ZoomEye is now a fourth exposure intelligence source alongside Shodan, FOFA, and Censys. Strong Asia-Pacific and Middle East indexing complements the other three. Requires `ZOOMEYE_API_KEY` (free tier).
- **Shared HTTP connection pool** (`core/http_client.py`) — All HTTP traffic now flows through three persistent `httpx.Client` singletons (`api`, `scrape`, `scrape_noverify`) instead of creating a new client per request. Eliminates repeated TCP/TLS handshake overhead across all 14 fetchers and harvesters. Typical improvement: 2–5 seconds per full pipeline run.
- **CVE-first Oman search strategy** — The `/analyze/oman` endpoint now auto-fetches the top 5 CVEs from NVD (sorted by CVSS score) when none are supplied by the caller. Searching by CVE ID rather than software name produces significantly more targeted exposure results.
- **Standalone Oman Intel section** — The Oman Internet Exposure panel in the web UI is now always visible, independent of the main analysis. Users can query exposure directly without running the full pipeline first. Includes a "Copy from analysis" button to pre-fill from the main form.
- **Per-source diagnostics** — Each Oman Intel source card has a collapsible diagnostics panel showing the exact query sent, HTTP status codes, and match counts. Helps diagnose 0-result returns without guessing.
- **`ATTACKERKB_API_KEY` configuration** — Added to `core/config.py`, `core/rate_limiter.py`, `.env.example`, and the `/health` endpoint key-status response.
- **`ZOOMEYE_API_KEY` configuration** — Added to all the same locations.
- **Source icon labels in Stage 3** — PoC source names now render with icons (`🐙 GitHub`, `📋 Pastebin`, `🔫 Metasploit`, `⚡ Packet Storm`, `🎯 Nuclei`, `🗃 Exploit-DB`, `🇨🇳 Gitee`, `🇨🇳 Seebug`) instead of raw enum strings.
- **Project Roadmap card** — About section in the web UI now shows a roadmap of completed and planned features.
- **`PASTEBIN` value in `PoCSource` enum** — Extends the existing source taxonomy.

### Changed

- **Stage 1 concurrency** — Thread pool expanded from 4 to 5 workers to accommodate the new AttackerKB source alongside NVD, OSV, GHSA, and the misconfig mapper.
- **Stage 3 concurrency** — Thread pool per CVE expanded from 7 to 8 workers to accommodate Pastebin alongside the existing six sources.
- **`sources_queried` in Stage 3** — Now lists every source that was *attempted*, not only sources that returned results. A user can confirm that Pastebin was searched even when it found nothing.
- **`/analyze/stream` and `/analyze/full`** — Both endpoints now forward `nvd_api_key` and `attackerkb_api_key` from server settings so authenticated rate limits apply during web UI analysis.
- **Shodan query strategy** — CVE searches changed from `vuln:CVE-xxxx` (requires a paid plan) to keyword search `"CVE-xxxx" country:OM`, which works on the free tier. Product searches changed from banner text matching to `product:"name" country:OM` for reliable free-tier counts.
- **Source list rendering** — All `sources_queried` lists in the web UI now pass through the `sourceLabel()` function for consistent icon formatting.

### Fixed

- `cache.set()` wrong signature in `oman_intel.py` — calls were passing `ttl=` as a keyword argument instead of the correct positional `ttl_seconds=`, raising `TypeError` whenever Oman Intel results were written to cache.
- Shodan `vuln:` filter returning 0 — the filter requires a paid account. Replaced with keyword-based CVE search compatible with the free tier.
- ZoomEye API domain — corrected from `api.zoomeye.org` (returns HTTP 403 with a redirect hint) to `api.zoomeye.ai`.
- Real API keys accidentally included in `.env.example` — both the Gemini key and the FOFA key have been blanked.

---

## [0.3.0] — 2026-04-01

### Added

- **AI Verdict (Stage 4)** — Gemini 2.5 Flash synthesises all pipeline evidence into a final risk verdict: `PATCH NOW`, `HIGH`, `MONITOR`, or `DEFER`. Includes a confidence score and plain-English reasoning. A deterministic rule-based engine is used as fallback when `GEMINI_API_KEY` is not set, ensuring the verdict stage always produces output.
- **Streaming pipeline** (`GET /analyze/stream`) — Server-Sent Events endpoint that emits each stage result as soon as it completes. The web UI renders CVE data within seconds while exploit harvesting continues in the background.
- **Real-time web dashboard** — Four-tab interface (CVE Inventory, Exploitability, Public PoCs, AI Verdict) with progressive rendering, severity badges, EPSS probability bars, version-compatibility indicators, and a final verdict card.
- **International exploit sources** (`core/intl_harvester.py`) — Parallel search across Gitee and Seebug (China), CNVD (China national database), Yandex and Baidu (Russian/Chinese web search), and Naver (Korea). Results displayed in a dedicated "International Results" section separated from English-language sources.
- **Metasploit harvester** (`core/metasploit_harvester.py`) — Searches the `rapid7/metasploit-framework` GitHub repository for modules that reference each CVE. Matches are classified as WEAPONIZED by definition.
- **Packet Storm harvester** (`core/packet_storm_harvester.py`) — Scrapes `packetstormsecurity.com` search results for each CVE ID.
- **GHSA fetcher** (`core/ghsa_fetcher.py`) — GitHub Security Advisories via the GraphQL API. Third parallel CVE source in Stage 1 alongside NVD and OSV.
- **VulnCheck integration** (`core/vulncheck_fetcher.py`) — APT group and ransomware attribution per CVE via the VulnCheck community API. Populates `threat_intel` fields in Stage 2 enrichments. Requires `VULNCHECK_API_KEY`.
- **Exploit-DB harvester** (`core/exploitdb_harvester.py`) — Queries the Exploit Database for matching entries. Works offline using a bundled local copy when available, falls back to live search.
- **Stage 2 feed back into Stage 3** — After harvesting, Stage 3 upgrades `exploit_maturity` in Stage 2 enrichments when WEAPONIZED or FUNCTIONAL PoCs are found. This ensures the final verdict reflects discovered exploit evidence.
- **Full pipeline endpoint** (`POST /analyze/full`) — Runs all stages and returns a single JSON response.
- **SBOM analysis endpoint** (`POST /analyze/sbom`) — Accepts CycloneDX JSON, SPDX JSON, and `requirements.txt`. Runs the full pipeline on every component in the bill of materials.
- **Delta tracking endpoint** (`POST /analyze/delta`) — Compares the current run against the last saved snapshot for the same software and version. Returns new CVEs, tier upgrades, EPSS score changes, and newly discovered exploits.
- **Demo endpoints** — `GET /demo/log4shell` and `GET /demo/spring4shell` return pre-computed fixture data instantly, no network required. Useful for demos and testing.
- **CLI** (`cli/vael.py`) — Full-featured command-line interface built with Typer and Rich. Supports `--stage`, `--verdict`, `--json`, `--offline`, `--deterministic`, `--ecosystem`, `--skip-nvd`, `--skip-github`, and `--verbose` flags.
- **Name resolver** (`core/name_resolver.py`) — Fuzzy canonical name matching using rapidfuzz. Resolves aliases such as `log4j`, `log4j2`, and `log4j-core` to the same NVD search term before querying data sources.
- **Report generator** (`core/report_generator.py`) — Exports full analysis results as structured Markdown or JSON.
- **SBOM parser** (`core/sbom_parser.py`) — Parses CycloneDX JSON, SPDX JSON, and pip `requirements.txt` into a normalised component list for batch analysis.
- **Rate limit warnings** — Pipeline results include a `rate_limit_warnings` list surfaced in the web UI when any API budget is running low.
- **`/health` endpoint** — Returns server liveness and masked key-configuration status for all optional API integrations.
- **`/rate-limits` endpoint** — Per-API remaining budget, session usage counts, throttle event totals, and upgrade tips.
- **Offline mode** — Pass `--offline` via CLI or `offline=true` via API to use only cached data and make no outbound network requests.
- **Docker support** — `Dockerfile` (multi-stage build), `docker-compose.yml` (gunicorn + nginx), `gunicorn.conf.py` (multi-worker with 120-second pipeline timeout, `/dev/shm` heartbeat files).
- **nginx configuration** — Reverse proxy with `proxy_buffering off` on `/analyze/stream` for correct SSE delivery, gzip compression, security headers.

### Changed

- **Stage 1 concurrency** — Expanded from 2 to 4 parallel workers: NVD, OSV, GHSA, and the misconfig mapper now run simultaneously.
- **Stage 3 concurrency** — Expanded to 7 workers per CVE: GitHub, Exploit-DB, Nuclei, Packet Storm, Metasploit, and international sources all run in parallel.
- **Verdict labels** — Renamed internal tier identifiers to user-facing labels: `T0_PATCH_NOW` → `PATCH NOW`, `T1_HIGH` → `HIGH`, `T2_MONITOR` → `MONITOR`, `T3_DEFER` → `DEFER`.

---

## [0.2.0] — 2026-03-01

### Added

- **Stage 2 — Exploitability Scoring** — Each CVE discovered in Stage 1 is enriched with:
  - **EPSS score** (Exploit Prediction Scoring System) — probability of exploitation in the next 30 days, sourced from FIRST.org.
  - **CISA KEV membership** — flag indicating whether the CVE appears on the US government's Known Exploited Vulnerabilities catalog.
  - **VEP tier assignment** — internal priority classification (`T0_PATCH_NOW`, `T1_HIGH`, `T2_MONITOR`, `T3_DEFER`) based on EPSS threshold, KEV presence, and exploit maturity signal.
- **Stage 3 — Exploit Harvesting (initial)** — GitHub and Exploit-DB search for public PoC code. Per-repo quality classification: WEAPONIZED, FUNCTIONAL, CONCEPTUAL, FAKE, UNKNOWN. Version compatibility detection via README and description text analysis.
- **OSV fetcher** (`core/osv_fetcher.py`) — Google's Open Source Vulnerabilities database as a second Stage 1 source. Significantly improves coverage for Python, Go, Rust, npm, and Maven packages.
- **EPSS fetcher** (`core/epss_fetcher.py`) — Downloads the daily EPSS CSV feed from FIRST.org and caches it locally. Falls back to single-CVE REST API lookup when the feed is unavailable.
- **KEV fetcher** (`core/kev_fetcher.py`) — Downloads and caches the CISA Known Exploited Vulnerabilities JSON catalog. Daily refresh with local cache.
- **GitHub harvester** (`core/github_harvester.py`) — Searches GitHub code and repositories for PoC code matching each CVE ID. Fetches README content for deep quality analysis of top results. Detects fake/star-inflated repositories. Supports authenticated requests via `GITHUB_TOKEN` for higher rate limits (5,000 req/hr vs 60).
- **Exploit-DB harvester** (`core/exploitdb_harvester.py`) — Queries the Exploit Database for CVE matches. Supports offline local copy.
- **Nuclei harvester** (`core/nuclei_harvester.py`) — Checks the `projectdiscovery/nuclei-templates` GitHub repository for a YAML template matching each CVE. A matching Nuclei template is classified as WEAPONIZED.
- **`/analyze/exploit` endpoint** — Runs Stages 1 and 2, returns exploitability enrichments without harvesting exploits.
- **`/analyze/pocs` endpoint** — Runs Stages 1, 2, and 3.
- **SQLite cache layer** (`core/cache.py`) — Replaces scattered per-module JSON file caches with a single `vael_cache.db`. Entries carry TTL expiry, zlib compression, and source-indexed lookups. Cache path is configurable via `CACHE_DIR` / `CACHE_DB` settings.
- **Rate limiter** (`core/rate_limiter.py`) — Centralised per-API budget tracker. Reads standard rate-limit response headers (GitHub `x-ratelimit-*`, FOFA `x-fofa-quota-remaining`). Tracks 429 and 403 exhaustion events. Warns when remaining budget falls below a configurable threshold.
- **Ecosystem detection** — `resolve_ecosystem()` in `core/name_resolver.py` maps software names to OSV ecosystem identifiers (PyPI, Maven, npm, Go, RubyGems, etc.) to improve OSV query recall.
- **Version matching** — CPE 2.3 string construction via `core/version_utils.py`. Checks whether the user-supplied version falls within each CVE's affected version ranges.
- **`GITHUB_TOKEN` support** — Authenticating GitHub requests raises the search API limit from 10 to 30 requests per minute and the REST API limit from 60 to 5,000 per hour.

### Changed

- **Stage 1 output schema** — `CVERecord` extended with `version_matched` flag, `cpe_matches` list, and `affected_versions_raw` for downstream version compatibility checks.
- **Web UI** — Added Stage 2 exploitability tab with EPSS scores, KEV badges, and VEP tier indicators. Stage 3 tab shows PoC cards with quality badges and version compatibility labels.
- **`/analyze` endpoint** — Response schema updated to include Stage 2 enrichments when `stage >= 2`.

### Fixed

- NVD pagination — requests beyond the first page were dropped when `startIndex` was not incremented correctly after the first page of results.
- OSV empty ecosystem query — sending an empty `ecosystem` key caused OSV to reject the request with HTTP 400. Now omitted from the payload when not set.

---

## [0.1.0] — 2026-02-01

### Added

- **Stage 1 — CVE Discovery** — Queries the NVD REST API v2 for CVEs matching a software name and version string. Returns a structured list of `CVERecord` objects with CVE ID, CVSS v2/v3 scores, severity, CWE classifications, affected version ranges, and references.
- **NVD fetcher** (`core/nvd_fetcher.py`) — Paginated NVD REST API v2 client with retry logic (3 attempts, exponential backoff). Supports `NVD_API_KEY` for the 10× higher authenticated rate limit. Caches results per query to avoid redundant API calls on repeated runs.
- **Misconfig mapper** (`core/misconfig_mapper.py`) — Local lookup against a curated CIS and CWE rule set. Flags common misconfigurations relevant to the queried software without making any network calls.
- **REST API** (`api/main.py`) — FastAPI application. Single endpoint: `POST /analyze` returns Stage 1 results as JSON.
- **Web UI** (`web/index.html`) — Single-page dashboard. Submits the analysis form, polls for results, and renders a CVE table with severity badges, CVSS scores, version-match indicators, and CWE tags.
- **CLI** (`cli/vael.py`) — Minimal command-line interface. Accepts `--software` and `--version` flags, prints a Rich-formatted CVE table to the terminal.
- **Pydantic schemas** (`schemas/stage1.py`) — `CVERecord`, `CVSSv3`, `CVSSv2`, `CWEEntry`, `CPEMatch`, `Reference`, `Stage1Result`, `MisconfigFlag`.
- **Config** (`core/config.py`) — pydantic-settings based configuration. Reads `.env`, environment variables, and Docker `/run/secrets/` files. Documented in `.env.example`.
- **`/docs` endpoint** — Interactive Swagger UI for exploring and testing the API.
- **`requirements.txt`** — Pinned dependencies: `fastapi`, `uvicorn`, `httpx`, `pydantic`, `pydantic-settings`, `typer`, `rich`, `packaging`, `pytest`.
