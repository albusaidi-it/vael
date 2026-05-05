# VAEL — Vulnerability Analysis Engine

**v0.4.0** · Open-source · Local-first · AI-assisted

> *Know whether to patch now or sleep soundly — in seconds, not hours.*

VAEL is an automated vulnerability analysis pipeline that takes a software name and version, then delivers a prioritized, evidence-backed risk decision by correlating data from a dozen public security feeds and harvesting live exploit code from across the internet — including non-English sources.

---

## The Problem

A typical security team faces this every week:

1. A scanner flags 47 CVEs against a dependency.
2. Someone has to manually check NVD, EPSS, CISA KEV, search GitHub for exploits, read advisories…
3. Two hours later: *"Probably patch it, but not urgent."*

That manual correlation is exactly what VAEL automates. It produces a single verdict — `PATCH NOW`, `HIGH`, `MONITOR`, or `DEFER` — with the evidence chain that justifies it.

---

## How It Works

```
Software + Version
       │
  ┌────▼────┐
  │ Stage 1 │  CVE Discovery        ← NVD · OSV · GHSA · CWE/CIS
  └────┬────┘
  ┌────▼────┐
  │ Stage 2 │  Exploitability       ← EPSS · CISA KEV · VulnCheck (APT/ransomware)
  └────┬────┘
  ┌────▼────┐
  │ Stage 3 │  PoC Harvesting       ← GitHub · Exploit-DB · Metasploit · Packet Storm
  │         │  (12 sources)         ← Nuclei · Gitee · Seebug · Naver · Yandex · Baidu
  └────┬────┘
  ┌────▼────┐
  │ Stage 4 │  Internet Exposure    ← Shodan · Censys
  └────┬────┘
  ┌────▼────┐
  │ Verdict │  AI Risk Decision     ← Gemini AI (deterministic fallback built-in)
  └─────────┘
       │
  PATCH NOW / HIGH / MONITOR / DEFER
```

---

## Quick Start

```bash
git clone <repo>
cd vael
pip install -r requirements.txt

# Start the web UI + API
uvicorn api.main:app --reload
# → Open http://localhost:8000
```

Or via CLI:

```bash
# Full pipeline — stages 1-3 + AI verdict
python cli/vael.py analyze --software log4j --version 2.14.1

# JSON output for integrations
python cli/vael.py analyze --software nginx --version 1.20.0 --json

# Offline mode (uses cached data only)
python cli/vael.py analyze --software django --version 3.2.0 --offline
```

---

## Key Features

| Feature | Details |
|---------|---------|
| **Multi-source CVE discovery** | NVD, OSV, GHSA — all queried in parallel, deduplicated |
| **Real exploitability scoring** | EPSS probability + CISA KEV presence + VulnCheck APT/ransomware intel |
| **Live PoC harvesting** | 12 sources including GitHub, Exploit-DB, Metasploit, Packet Storm |
| **International search** | Gitee 🇨🇳, Seebug 🇨🇳, Naver 🇰🇷, Yandex 🇷🇺, Baidu 🇨🇳 with native-language queries |
| **Internet exposure** | Shodan + Censys attack-surface estimation |
| **AI verdict** | Gemini-powered risk decision with deterministic fallback |
| **SBOM support** | CycloneDX, SPDX, requirements.txt — analyze whole dependency trees |
| **Delta tracking** | Diff runs over time: new CVEs, tier upgrades, EPSS spikes, new PoCs |
| **Rate-limit aware** | Real-time budget tracking for all APIs, warnings surfaced to UI |
| **Web dashboard** | Live SSE-streaming results with progressive rendering |
| **Docker-ready** | Single `docker-compose up` deployment |

---

## All Zero Keys Required

Every API key is optional. Without keys:
- NVD is rate-limited to 5 req/30s (still works)
- GitHub PoC search runs at 10 req/min unauthenticated
- VulnCheck, Shodan, Censys simply skip (pipeline still completes)
- Gemini falls back to deterministic rule-based verdict

---

## API

```bash
# SSE streaming (progressive rendering)
GET /analyze/stream?software=log4j&version=2.14.1

# Full pipeline
POST /analyze/full

# SBOM analysis
POST /analyze/sbom   (upload CycloneDX / SPDX / requirements.txt)

# Delta diff (what changed since last run)
POST /analyze/delta

# Internet exposure (Shodan + Censys)
POST /analyze/exposure

# Rate limit status
GET /rate-limits

# Demo scenarios (no network needed)
GET /demo/log4shell
GET /demo/spring4shell
```

Full interactive docs: `http://localhost:8000/docs`

---

## Configuration

Copy `.env.example` to `.env` and fill in any keys you have:

```bash
cp .env.example .env
```

| Variable | Source | Benefit |
|----------|--------|---------|
| `NVD_API_KEY` | nvd.nist.gov | 10× rate limit (50 req/30s) |
| `GITHUB_TOKEN` | github.com/settings/tokens | 83× rate limit (5000 req/hr) |
| `GEMINI_API_KEY` | aistudio.google.com | Enables AI verdict |
| `VULNCHECK_API_KEY` | vulncheck.com/register | APT + ransomware attribution |
| `SHODAN_API_KEY` | shodan.io | Internet exposure counts |
| `CENSYS_API_ID/SECRET` | censys.io | Exposure verification |

---

## Docker

```bash
docker-compose up
# → http://localhost:8000
```

---

## Project Structure

```
vael/
├── api/main.py              # FastAPI — REST + SSE endpoints
├── cli/vael.py              # Typer CLI
├── core/
│   ├── cve_mapper.py        # Stage 1 orchestrator
│   ├── exploit_eval.py      # Stage 2 orchestrator
│   ├── poc_harvester.py     # Stage 3 orchestrator
│   ├── exposure_checker.py  # Stage 4 (Shodan/Censys)
│   ├── ai_reasoner.py       # Gemini + deterministic fallback
│   ├── intl_harvester.py    # International sources (Gitee/Seebug/Naver/Yandex/Baidu)
│   ├── rate_limiter.py      # Central API budget tracker
│   ├── cache.py             # SQLite cache (WAL, zlib-compressed)
│   ├── delta_tracker.py     # Baseline snapshots + diff
│   └── sbom_parser.py       # CycloneDX / SPDX / requirements.txt
├── schemas/                 # Pydantic models for every stage
├── wiki/                    # Detailed documentation
├── web/index.html           # Single-file dashboard UI
├── fixtures/                # Offline demo data
└── docker-compose.yml
```

---

## Wiki

Detailed documentation lives in [`wiki/`](wiki/):

| Page | Contents |
|------|----------|
| [Overview](wiki/01-overview.md) | What VAEL is, the problem it solves, what the verdicts mean |
| [Architecture](wiki/02-architecture.md) | How the pipeline works — plain English + technical detail |
| [Installation](wiki/03-installation.md) | Setup for dev, production, Docker |
| [Usage](wiki/04-usage.md) | Web UI, CLI, API endpoints, interpreting results |
| [Pipeline Stages](wiki/05-stages.md) | Each stage in technical depth |
| [Data Sources](wiki/06-sources.md) | Every source, what it provides, rate limits |
| [API Keys](wiki/07-api-keys.md) | How to get and configure each key |
| [Contributing](wiki/08-contributing.md) | How to add new sources or stages |
| [Glossary](wiki/09-glossary.md) | Plain-English definitions for every term |

---

## License

MIT
