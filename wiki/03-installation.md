# Installation

## Requirements

- Python 3.10 or newer
- pip (Python's package installer, included with Python)
- Internet access (optional but strongly recommended — without it, only cached data is available)

No API keys are required to run. VAEL works with zero configuration and degrades gracefully when data sources are unavailable. See [API Keys](07-api-keys.md) if you want faster queries and more features.

---

## Quick Start

```bash
git clone <repo>
cd vael

# Create a virtual environment — an isolated Python environment
# so VAEL's packages don't conflict with anything else on your system
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install all required packages
pip install -r requirements.txt

# Start the web server
uvicorn api.main:app --reload
```

Open `http://localhost:8000` in your browser. That's it.

---

## Environment Variables

Copy the example file and fill in any keys you have:

```bash
cp .env.example .env
```

All keys are optional. The pipeline degrades gracefully without them:

| Variable | Default behavior without it |
|----------|-----------------------------|
| `NVD_API_KEY` | Rate-limited to 5 requests / 30 seconds |
| `GITHUB_TOKEN` | Rate-limited to 10 requests / minute |
| `GEMINI_API_KEY` | Deterministic rule-based verdict instead of AI |
| `VULNCHECK_API_KEY` | Threat actor and ransomware attribution skipped |
| `SHODAN_API_KEY` | Oman / Stage 4 exposure check skipped for Shodan |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | Censys skipped in Oman and Stage 4 checks |
| `FOFA_API_KEY` + `FOFA_EMAIL` | FOFA skipped in Oman exposure check (both required together) |
| `ZOOMEYE_API_KEY` | ZoomEye skipped in Oman exposure check |

### Where to get keys

| Key | URL |
|-----|-----|
| NVD | https://nvd.nist.gov/developers/request-an-api-key |
| GitHub | https://github.com/settings/tokens (scope: `public_repo`) |
| Gemini | https://aistudio.google.com/app/apikey |
| VulnCheck | https://vulncheck.com/register |
| Shodan | https://account.shodan.io/register |
| Censys | https://accounts.censys.io/register |
| FOFA | https://fofa.info/ (requires both `FOFA_API_KEY` and `FOFA_EMAIL`) |
| ZoomEye | https://www.zoomeye.ai/ |

See [API Keys](07-api-keys.md) for a detailed step-by-step guide for each.

---

## Docker

The simplest production deployment is a single Docker Compose command:

```bash
# Build and start
docker-compose up

# With API keys
NVD_API_KEY=your_key GITHUB_TOKEN=your_token docker-compose up
```

The web UI is served at `http://localhost:8000`.

The compose file mounts a named volume (`vael-cache`) so the SQLite cache persists across container restarts. Fixtures are mounted read-only for offline demos.

### Custom Docker build

```bash
docker build -t vael:latest .
docker run -p 8000:8000 \
  -e GEMINI_API_KEY=your_key \
  -e GITHUB_TOKEN=your_token \
  -v vael-cache:/tmp/vael_cache \
  vael:latest
```

---

## Cache Location

VAEL writes a SQLite database to `feeds/vael_cache.db` (relative to the working directory). This file is created automatically. In Docker it maps to the `vael-cache` named volume.

The cache survives restarts and dramatically reduces API usage on repeated queries. To clear it:

```bash
rm feeds/vael_cache.db
```

---

## Offline Mode

If you have no internet access, start the server normally and use the `/demo/` endpoints, which serve pre-computed fixture data:

```bash
GET /demo/log4shell       # log4j 2.14.1 – full pipeline output
GET /demo/spring4shell    # Spring Framework 5.3.17 – full pipeline output
```

From the CLI, pass `--offline` to use cached data only:

```bash
python cli/vael.py analyze --software log4j --version 2.14.1 --offline
```

---

## Key Dependencies

| Package | What it does |
|---------|-------------|
| `fastapi` + `uvicorn` | Powers the web server and REST API |
| `httpx` | Makes HTTP requests to external data sources |
| `pydantic` | Validates and structures all data flowing through the pipeline |
| `typer` + `rich` | Powers the command-line interface with formatted output |
| `beautifulsoup4` | Reads HTML from Packet Storm, Seebug, and CNVD pages |
| `rapidfuzz` | Fuzzy text matching for recognizing software name variations |
| `packaging` | Compares version numbers (e.g., "is 2.14.1 in the range 2.0–2.15.0?") |
| `google-generativeai` | Connects to Gemini AI for the final verdict |
| `gunicorn` | Production process manager — runs multiple server workers |
