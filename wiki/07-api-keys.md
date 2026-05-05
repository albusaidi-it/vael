# API Keys

All API keys are optional. VAEL degrades gracefully without any of them. This page explains how to obtain each one, what it unlocks, and where to configure it.

---

## Configuration

All keys are set via environment variables, either in a `.env` file or in your shell:

```bash
cp .env.example .env
# Edit .env with your keys
```

Or export directly:

```bash
export NVD_API_KEY=your_key
export GITHUB_TOKEN=ghp_yourtoken
export GEMINI_API_KEY=AIzaSy...
```

Keys are read by `core/config.py` using pydantic-settings. In Docker, pass them as environment variables to the container — see [Installation](03-installation.md).

---

## NVD API Key

**Variable:** `NVD_API_KEY`

**Why you want it:** Without a key, NVD rate-limits you to 5 requests per 30 seconds. With a key, you get 50 requests per 30 seconds (10× faster). For software with many CVEs (e.g., Apache, OpenSSL), this significantly reduces Stage 1 time.

**How to get it:**

1. Go to https://nvd.nist.gov/developers/request-an-api-key
2. Enter your email address
3. Check your email for the confirmation link
4. The API key arrives in a follow-up email (usually within a few minutes)

**Free?** Yes, completely free.

**Scopes needed:** None — the key is just a rate limit upgrade.

---

## GitHub Personal Access Token

**Variable:** `GITHUB_TOKEN`

**Why you want it:** Without a token, GitHub's search API allows 10 requests per minute. With a token, you get 5,000 requests per hour (500× more). For a query targeting 5 CVEs across GitHub, Metasploit, and Nuclei, this avoids rate limit errors and returns richer results.

**How to get it:**

1. Go to https://github.com/settings/tokens
2. Click **Generate new token (classic)**
3. Give it a descriptive name: `VAEL PoC Harvester`
4. Set expiration (90 days recommended for security)
5. Check only the `public_repo` scope under **repo**
6. Click **Generate token**
7. Copy the token immediately — GitHub will not show it again

**Free?** Yes. You only need read access to public repositories.

**Note:** A fine-grained personal access token also works. Grant "Read access to public repositories" for repository contents and metadata.

---

## Google Gemini API Key

**Variable:** `GEMINI_API_KEY`

**Why you want it:** Without a Gemini key, VAEL uses its built-in deterministic rule engine for the final verdict. The deterministic engine is reliable but produces simpler reasoning. Gemini synthesizes all evidence into a more nuanced, context-aware explanation and can surface non-obvious patterns.

**How to get it:**

1. Go to https://aistudio.google.com/app/apikey
2. Sign in with a Google account
3. Click **Create API key**
4. Select or create a project
5. Copy the key

**Free?** The free tier is generous (60 requests per minute on Flash models). VAEL makes one Gemini call per pipeline run, so even a free key is sufficient for normal use.

**Model configuration:** The default model is `gemini-2.5-flash`. Override with:
```bash
GEMINI_MODEL=gemini-2.5-flash
```

---

## VulnCheck API Key

**Variable:** `VULNCHECK_API_KEY`

**Why you want it:** VulnCheck provides APT group and ransomware attribution per CVE. Without it, the `threat_intel` fields in Stage 2 are empty — you still get EPSS and KEV, but you miss information like "APT41 has used this CVE" or "LockBit ransomware exploits this."

**How to get it:**

1. Go to https://vulncheck.com/register
2. Register for a free community account
3. Verify your email
4. Go to **Account → API Tokens**
5. Generate a token

**Free?** Yes, the community tier is free and provides access to the initial-access and ransomware indexes used by VAEL.

---

## Shodan API Key

**Variable:** `SHODAN_API_KEY`

**Why you want it:** Enables Shodan searches in the **Oman Internet Exposure** section (and Stage 4 global exposure analysis). Without it, Shodan results are skipped entirely.

**How to get it:**

1. Go to https://account.shodan.io/register
2. Create an account
3. The API key is displayed on your account page immediately after registration

**Free?** The free tier provides an API key and is sufficient for most VAEL use cases.

### Free tier vs. paid plan

| Feature | Free tier | Paid plan |
|---------|-----------|-----------|
| `/shodan/host/count` (totals) | ✓ Works | ✓ Works |
| `/shodan/host/search` (host samples) | ✓ Works (1 credit/query) | ✓ Works |
| `product:` filter | ✓ Works | ✓ Works |
| `vuln:` filter (search by CVE ID) | ✗ Returns 0 | ✓ Works |

**What this means in practice:** With a free Shodan key, VAEL uses `product:"apache" country:OM` to find exposed hosts — this is reliable and returns real counts. The CVE-targeted row in the Oman table will show 0 from Shodan on the free tier because the `vuln:` filter requires a paid account. FOFA and Censys fill this gap if those keys are configured.

---

## Censys API Key

**Variables:** `CENSYS_API_ID` and `CENSYS_API_SECRET`

**Why you want it:** Provides cross-validation of Shodan exposure data using a different scanning methodology. Censys is stronger on TLS certificate data, which helps identify internet-facing services that don't announce their software version in banners.

**How to get it:**

1. Go to https://accounts.censys.io/register
2. Create an account (email required)
3. After login, go to **My Account → API**
4. Copy the **API ID** (this is `CENSYS_API_ID`) and the **Secret** (this is `CENSYS_API_SECRET`)

**Free?** Yes. The free tier includes 250 search queries per month, which is sufficient for security teams running VAEL a few times per week.

---

## ZoomEye API Key

**Variable:** `ZOOMEYE_API_KEY`

**Why you want it:** ZoomEye is a Chinese internet intelligence platform with strong coverage of Asia-Pacific and Middle East networks, complementing Shodan and FOFA in the **Oman Internet Exposure** section. It often indexes different hosts than Shodan, increasing the overall coverage.

**How to get it:**

1. Go to https://www.zoomeye.ai/
2. Click **Sign Up** and create a free account
3. After login, go to **Profile → API Key**
4. Copy the API key

**Free?** Yes. The free tier provides access to search results (10,000 results/month).

**Authentication:** ZoomEye uses `Authorization: JWT <key>` — different from Shodan's `?key=` parameter style. VAEL handles this automatically.

**Query format:** VAEL searches ZoomEye using `app:"software" country:"Oman"` for product searches and `"CVE-xxxx" country:"Oman"` for CVE-targeted searches.

---

## FOFA API Key

**Variables:** `FOFA_API_KEY` and `FOFA_EMAIL`

**Why you want it:** FOFA is a Chinese internet intelligence platform with strong coverage of the Middle East and Asia-Pacific region — often finding hosts that Shodan or Censys miss. It is the most useful additional source for the **Oman Internet Exposure** section. Both variables must be set together; setting only one has no effect.

**How to get it:**

1. Go to https://fofa.info/
2. Click **Register** and create an account
3. After login, go to **Personal Center → API**
4. Copy your **API Key** (`FOFA_API_KEY`) and note your registered **email address** (`FOFA_EMAIL`)

**Free?** FOFA has a free tier with limited monthly queries. The F plan provides 10,000 queries per month.

**Query format:** VAEL searches FOFA using: `app="software" && country="OM"` for product searches, and `"CVE-xxxx" && country="OM"` for CVE-targeted searches.

**Note:** Both `FOFA_API_KEY` and `FOFA_EMAIL` must be set. The FOFA API requires the account email as an additional authentication parameter alongside the key.

---

## Priority Order

If you can only get a few keys, this is the recommended priority:

1. **`GITHUB_TOKEN`** — highest impact; enables PoC harvesting at full speed
2. **`GEMINI_API_KEY`** — enables AI-quality reasoning vs. deterministic rules
3. **`NVD_API_KEY`** — speeds up Stage 1 for software with many CVEs
4. **`VULNCHECK_API_KEY`** — adds threat actor context to high-priority CVEs
5. **`SHODAN_API_KEY`** — enables Oman exposure and Stage 4 global analysis
6. **`FOFA_API_KEY` + `FOFA_EMAIL`** — adds Middle East/APAC coverage to Oman Intel
7. **`ZOOMEYE_API_KEY`** — adds ZoomEye coverage to Oman Intel (strong APAC/Middle East indexing)
8. **`CENSYS_API_ID/SECRET`** — adds Censys cross-validation for exposure analysis

The pipeline is fully functional with zero keys — the above order reflects which upgrades have the most noticeable impact on result quality.

For the **Oman Internet Exposure** section specifically, keys 5–8 are what matter. Together, Shodan + FOFA + ZoomEye + Censys give the broadest coverage of publicly reachable hosts in Oman.
