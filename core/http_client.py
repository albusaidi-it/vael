"""
VAEL – Shared persistent httpx clients.

Creating httpx.Client() per call throws away the connection pool on every
request — meaning a fresh TCP handshake + TLS negotiation every time.
Sharing a client keeps connections alive and re-uses them across calls.

Three clients cover every use case in the codebase:
  api           — JSON APIs (NVD, GitHub, EPSS, KEV, OSV, GHSA, VulnCheck …)
  scrape        — HTML scraping with a browser User-Agent (Packet Storm, Pastebin …)
  scrape_noverify — Same but TLS verification disabled (some Chinese platforms)

All three are module-level singletons — safe for concurrent use from multiple
threads (httpx connection pools are thread-safe).
"""
from __future__ import annotations

import httpx

_LIMITS = httpx.Limits(
    max_connections=100,
    max_keepalive_connections=30,
    keepalive_expiry=30,
)

_BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_SCRAPE_HEADERS = {
    "User-Agent": _BROWSER_UA,
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# JSON API calls — no default auth headers; pass per-request as needed
api = httpx.Client(
    timeout=30,
    follow_redirects=True,
    limits=_LIMITS,
)

# Browser-like scraping — carries a realistic User-Agent
scrape = httpx.Client(
    headers=_SCRAPE_HEADERS,
    timeout=15,
    follow_redirects=True,
    limits=_LIMITS,
)

# Same as scrape but with TLS verification disabled for platforms that use
# self-signed or untrusted certificates (some Chinese intelligence platforms)
scrape_noverify = httpx.Client(
    headers=_SCRAPE_HEADERS,
    timeout=15,
    follow_redirects=True,
    verify=False,
    limits=_LIMITS,
)
