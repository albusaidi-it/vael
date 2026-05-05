"""
VAEL – Pastebin Harvester (Stage 3)
Scrapes pastebin.com search results for pastes mentioning a CVE ID.

Pastebin is a common dumping ground for PoC code and exploit scripts.
No auth required; scrapes public search at /search?q=CVE-xxxx.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

import httpx
from core import http_client
from bs4 import BeautifulSoup

from core import cache as _cache_mod
from core.rate_limiter import rate_limiter
from schemas.stage3 import PoCRecord, PoCSource, PoCQuality, VersionCompatibility

logger = logging.getLogger(__name__)

_BASE    = "https://pastebin.com"
_SEARCH  = f"{_BASE}/search"
_TTL     = 12 * 3600   # 12-hour cache

_PASTE_HREF   = re.compile(r"^/[A-Za-z0-9]{6,12}$")
_VERSION_LIKE = re.compile(r"\b\d+\.\d+(?:\.\d+)?\b")

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Pages we never want to follow
_SKIP_PATHS = {"/search", "/login", "/register", "/about", "/faq", "/tools",
               "/trends", "/archive", "/languages"}


def _version_compat(target_version: str, text: str) -> VersionCompatibility:
    if target_version and target_version in text:
        return VersionCompatibility.CONFIRMED
    if _VERSION_LIKE.search(text):
        return VersionCompatibility.LIKELY
    return VersionCompatibility.UNKNOWN


def _classify(title: str, snippet: str = "") -> PoCQuality:
    text = (title + " " + snippet).lower()
    if any(x in text for x in (
        "exploit", "rce", "remote code execution", "shell", "payload",
        "reverse shell", "bind shell", "command injection", "arbitrary code",
    )):
        return PoCQuality.FUNCTIONAL
    if any(x in text for x in (
        "poc", "proof of concept", "bypass", "injection", "working",
        "vulnerability", "vuln", "attack",
    )):
        return PoCQuality.CONCEPTUAL
    return PoCQuality.UNKNOWN


def search_pastebin(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    cache_key = _cache_mod.make_key("pastebin", cve_id)
    cached = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []

    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str]       = []

    try:
        resp = http_client.scrape.get(_SEARCH, params={"q": cve_id, "submit": "Search"})
        rate_limiter.record("pastebin", dict(resp.headers), resp.status_code)

        if resp.status_code == 429:
            errors.append(f"[RateLimit] Pastebin rate-limited for {cve_id}")
            return pocs, errors
        if not resp.is_success:
            errors.append(
                f"Pastebin search failed (HTTP {resp.status_code}) for {cve_id}"
            )
            return pocs, errors

        soup = BeautifulSoup(resp.text, "html.parser")
        seen_urls: set[str] = set()

        for a in soup.find_all("a", href=_PASTE_HREF):
            href = a["href"]
            # Skip non-paste paths
            if href in _SKIP_PATHS or href.startswith("/u/"):
                continue
            url = _BASE + href
            if url in seen_urls:
                continue

            title   = a.get_text(strip=True)
            parent  = a.parent
            snippet = parent.get_text(" ", strip=True) if parent else title

            # Keep only results that actually mention this CVE
            if cve_id.lower() not in snippet.lower() and cve_id.lower() not in title.lower():
                continue

            seen_urls.add(url)
            pocs.append(PoCRecord(
                cve_id=cve_id,
                source=PoCSource.PASTEBIN,
                url=url,
                title=title or None,
                quality=_classify(title, snippet),
                version_compatibility=_version_compat(target_version, snippet),
            ))

    except Exception as e:
        errors.append(f"Pastebin search error for {cve_id}: {e}")
        return pocs, errors

    logger.info("Pastebin found %d pastes for %s", len(pocs), cve_id)

    if pocs:
        _cache_mod.set(
            cache_key, "pastebin",
            [p.model_dump(mode="json") for p in pocs],
            _TTL,
        )
    return pocs, errors
