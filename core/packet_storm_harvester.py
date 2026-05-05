"""
VAEL – Packet Storm Security Harvester
Scrapes packetstormsecurity.com search results for a CVE ID.
Returns PoCRecord entries with source=PACKET_STORM.
"""
from __future__ import annotations

import logging
import re
from datetime import date
from typing import Optional

import httpx
from core import http_client
from bs4 import BeautifulSoup

from core import cache as _cache_mod
from core.rate_limiter import rate_limiter
from schemas.stage3 import PoCRecord, PoCSource, PoCQuality, VersionCompatibility

logger = logging.getLogger(__name__)

_BASE    = "https://packetstormsecurity.com"
_SEARCH  = f"{_BASE}/search/"
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
_TTL = 24 * 3600

# Month abbreviation map used in Packet Storm date strings ("January 01 2024")
_MONTHS = {m: i for i, m in enumerate(
    ["january","february","march","april","may","june",
     "july","august","september","october","november","december"], 1
)}


def _parse_date(text: str) -> Optional[date]:
    text = text.strip().lower()
    for month, num in _MONTHS.items():
        if month in text:
            m = re.search(r"(\d{1,2})[,\s]+(\d{4})", text)
            if m:
                try:
                    return date(int(m.group(2)), num, int(m.group(1)))
                except ValueError:
                    pass
    return None


def _classify(title: str) -> PoCQuality:
    t = title.lower()
    if any(x in t for x in ("metasploit", "msf module")):
        return PoCQuality.WEAPONIZED
    if any(x in t for x in ("remote code execution", "rce exploit", "shell exploit")):
        return PoCQuality.FUNCTIONAL
    if any(x in t for x in ("proof of concept", "poc")):
        return PoCQuality.CONCEPTUAL
    # Packet Storm curates working exploits by default
    return PoCQuality.FUNCTIONAL


def search_packet_storm(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    cache_key = _cache_mod.make_key("packet_storm", cve_id)
    cached = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []

    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str] = []

    try:
        resp = http_client.scrape.get(_SEARCH, params={"q": cve_id, "submit": "Search"})
        rate_limiter.record("packet_storm", dict(resp.headers), resp.status_code)

        if resp.status_code == 429:
            errors.append(f"[RateLimit] Packet Storm rate-limited for {cve_id}")
            return pocs, errors
        if not resp.is_success:
            errors.append(f"Packet Storm search failed ({resp.status_code}) for {cve_id}")
            return pocs, errors

        soup = BeautifulSoup(resp.text, "html.parser")

        # Packet Storm result rows: <dl> blocks with dt (title+link) and dd entries
        for dl in soup.select("dl"):
            dt = dl.find("dt")
            if not dt:
                continue
            a = dt.find("a", href=True)
            if not a:
                continue

            title = a.get_text(strip=True)
            href  = a["href"]
            url   = (_BASE + href) if href.startswith("/") else href

            # Only keep results that actually mention this CVE
            if cve_id.lower() not in title.lower() and cve_id.lower() not in url.lower():
                content_dd = dl.find("dd", class_="detail")
                if not content_dd or cve_id.lower() not in content_dd.get_text().lower():
                    continue

            # Parse date from the datetime <dd>
            published: Optional[date] = None
            date_dd = dl.find("dd", class_="datetime")
            if date_dd:
                published = _parse_date(date_dd.get_text())

            pocs.append(PoCRecord(
                cve_id=cve_id,
                source=PoCSource.PACKET_STORM,
                url=url,
                title=title,
                published=published,
                quality=_classify(title),
                version_compatibility=VersionCompatibility.UNKNOWN,
            ))

    except Exception as e:
        errors.append(f"Packet Storm search error for {cve_id}: {e}")
        return pocs, errors

    if pocs:
        _cache_mod.set(
            cache_key, "packet_storm",
            [p.model_dump(mode="json") for p in pocs],
            _TTL,
        )
    return pocs, errors
