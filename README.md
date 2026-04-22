# VAEL – Vulnerability Analysis Engine

**v0.3.0** · Stages 1–3 complete + Gemini AI verdict layer

Open-source, AI-driven vulnerability analysis engine.
Local-first · Modular · KEV-style risk decisions.

---

## Quick Start

```bash
pip install -r requirements.txt

# Export keys (all optional)
export NVD_API_KEY=...          # NVD rate limit boost
export GITHUB_TOKEN=...          # GitHub PoC search
export GEMINI_API_KEY=...        # AI verdict (fallback works without)

# ── Stage 1: CVE mapping ──
python cli/vael.py analyze --software log4j --version 2.14.1

# ── Stage 2: + exploitability (EPSS, KEV) ──
python cli/vael.py analyze --software log4j --version 2.14.1 --stage 2

# ── Stage 3: + PoC harvesting (GitHub, Exploit-DB, Nuclei) ──
python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3

# ── Full pipeline: stages 1-3 + AI verdict ──
python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3 --verdict

# ── JSON output for integration ──
python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3 --verdict --json

# ── REST API ──
uvicorn api.main:app --reload
# → http://localhost:8000/docs
```

---

## Pipeline Stages

### ✅ Stage 1 – Known Vulnerability Mapping
| Source | What it provides |
|--------|-----------------|
| NVD API v2 | CVE details, CVSS, CPE matches |
| OSV.dev | Open-source CVEs (PyPI, npm, Maven…) |
| CWE (local) | Common weakness patterns per software |
| CIS Benchmarks (local) | Hardening rule violations |

### ✅ Stage 2 – Real Exploitability Evaluation
| Source | What it provides |
|--------|-----------------|
| EPSS CSV (FIRST.org) | Exploit probability score (0–1) |
| CISA KEV (JSON feed) | Known-exploited-in-wild catalog |
| Heuristic patch detector | Fixed versions + vendor advisories |

**Output:** VEP (Vulnerability Exploitability Priority) tier per CVE:
- 🚨 **T0 PATCH NOW** — In KEV or EPSS > 0.7 AND version-matched
- ⚠️ **T1 HIGH** — Score ≥ 50
- 👁️ **T2 MONITOR** — Score ≥ 25
- 📋 **T3 DEFER** — No exploitation evidence

### ✅ Stage 3 – Public Exploit / PoC Harvesting
| Source | What it provides |
|--------|-----------------|
| GitHub Search API | Community PoC repos (with fake-repo filter) |
| Exploit-DB CSV | Curated exploit catalog |
| Nuclei templates | Weaponized scanner templates |

**Quality classification:**
- **WEAPONIZED** — Metasploit, Nuclei, trusted security researchers
- **FUNCTIONAL** — Working exploit code + stars + README
- **CONCEPTUAL** — Describes vuln, minimal code
- **FAKE** — Spam/empty/clickbait (filtered out)

### ✅ AI Reasoning Layer – Gemini
- Takes **pre-fetched facts only** — never retrieves information
- Produces KEV-style verdict: `PATCH NOW` / `HIGH` / `MONITOR` / `DEFER`
- JSON-schema-enforced output with confidence score
- **Always falls back to deterministic rule-based verdict** if Gemini unavailable

### 🔜 Upcoming
- **Stage 4** — Contextual exposure analysis (deployment profile)
- **Stage 5** — Attack path construction (CAPEC + ATT&CK graph)
- **Stage 6** — Full KEV-style decision aggregation

---

## Project Structure

```
vael/
├── core/
│   ├── cve_mapper.py           # Stage 1 orchestrator
│   ├── nvd_fetcher.py          # NVD API v2 client
│   ├── osv_fetcher.py          # OSV.dev client
│   ├── misconfig_mapper.py     # CWE + CIS local KB
│   ├── version_utils.py        # semver range matching
│   ├── exploit_eval.py         # Stage 2 orchestrator
│   ├── epss_fetcher.py         # EPSS CSV cache
│   ├── kev_fetcher.py          # CISA KEV JSON cache
│   ├── patch_detector.py       # Patch info extractor
│   ├── exploit_scorer.py       # VEP scoring algorithm
│   ├── poc_harvester.py        # Stage 3 orchestrator
│   ├── github_harvester.py     # GitHub PoC search + classifier
│   ├── exploitdb_harvester.py  # Exploit-DB CSV lookup
│   ├── nuclei_harvester.py     # Nuclei template checker
│   └── ai_reasoner.py          # Gemini + deterministic fallback
├── schemas/
│   ├── stage1.py               # CVE + misconfig models
│   ├── stage2.py               # Exploitability + VEP models
│   └── stage3.py               # PoC + quality models
├── api/main.py                  # FastAPI (4 endpoints)
├── cli/vael.py                  # Typer CLI
├── tests/
│   ├── test_stage1.py          # 14 tests
│   ├── test_stage2.py          # 16 tests
│   └── test_stage3.py          # 24 tests
└── requirements.txt
```

---

## Design Principles

1. **Local-first** — All heavy feeds (NVD JSON, EPSS CSV, KEV JSON, Exploit-DB CSV) cached locally; 24–72h TTL
2. **Modular** — Every stage works standalone; each harvester is independently disableable
3. **LLM as reasoner, never retriever** — Gemini receives pre-fetched structured data; prompt explicitly forbids invention
4. **Deterministic fallback** — Pipeline works end-to-end without Gemini; AI is an enhancement
5. **Rate-limit aware** — NVD, GitHub, EDB all have retry/backoff logic
6. **Structured output** — Every stage output is a Pydantic model; JSON mode preserves full data

---

## Testing

```bash
# Offline unit tests (no network)
VAEL_SKIP_INTEGRATION=1 python tests/test_stage1.py
VAEL_SKIP_INTEGRATION=1 python tests/test_stage2.py
VAEL_SKIP_INTEGRATION=1 python tests/test_stage3.py

# Full test suite (requires internet for NVD/OSV/EPSS/KEV/GitHub)
python tests/test_stage1.py
python tests/test_stage2.py
python tests/test_stage3.py
```

Test coverage: **54 tests total**, of which **48 are offline** (pure logic) and **6 are integration** (live feeds).
