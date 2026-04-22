"""
VAEL – Stage 2 / CISA KEV Fetcher
CISA Known Exploited Vulnerabilities catalog.

Strategy:
  - Full KEV catalog (~1000 entries) is a single JSON file
  - Download once, cache locally, refresh every 24h
  - In-memory dict lookup by CVE ID

Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional
import httpx

from schemas.stage2 import KEVEntry

logger = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_CACHE_DIR = Path(os.environ.get("VAEL_CACHE_DIR", "./feeds"))
CACHE_TTL = timedelta(hours=24)


def _parse_date(s: Optional[str]) -> Optional[date]:
    if not s:
        return None
    try:
        return date.fromisoformat(s.split("T")[0])
    except ValueError:
        return None


class KEVCache:
    """In-memory KEV catalog cache."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "cisa_kev.json"
        self._data: dict[str, KEVEntry] = {}
        self._loaded = False
        self._catalog_version: Optional[str] = None
        self._catalog_date: Optional[str] = None

    def _cache_is_stale(self) -> bool:
        if not self.cache_file.exists():
            return True
        mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
        return (datetime.now() - mtime) > CACHE_TTL

    def _download(self) -> bool:
        logger.info("Downloading CISA KEV catalog")
        try:
            with httpx.Client(timeout=30, follow_redirects=True) as client:
                resp = client.get(KEV_URL)
                resp.raise_for_status()
            self.cache_file.write_bytes(resp.content)
            logger.info("KEV cached: %d bytes", len(resp.content))
            return True
        except Exception as e:
            logger.error("Failed to download KEV: %s", e)
            return False

    def _parse(self) -> None:
        if not self.cache_file.exists():
            return
        try:
            with self.cache_file.open("r", encoding="utf-8") as f:
                catalog = json.load(f)

            self._catalog_version = catalog.get("catalogVersion")
            self._catalog_date    = catalog.get("dateReleased")

            for v in catalog.get("vulnerabilities", []):
                cve_id = v.get("cveID", "").upper().strip()
                if not cve_id:
                    continue
                self._data[cve_id] = KEVEntry(
                    cve_id=cve_id,
                    vendor_project=v.get("vendorProject"),
                    product=v.get("product"),
                    vulnerability_name=v.get("vulnerabilityName"),
                    date_added=_parse_date(v.get("dateAdded")),
                    short_description=v.get("shortDescription"),
                    required_action=v.get("requiredAction"),
                    due_date=_parse_date(v.get("dueDate")),
                    known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse"),
                    notes=v.get("notes"),
                )
            logger.info("Loaded %d KEV entries (v%s)", len(self._data), self._catalog_version)
        except Exception as e:
            logger.error("Failed to parse KEV: %s", e)

    def ensure_loaded(self, allow_download: bool = True) -> None:
        if self._loaded and self._data:
            return
        if self._cache_is_stale() and allow_download:
            self._download()
        self._parse()
        self._loaded = True

    def is_in_kev(self, cve_id: str) -> bool:
        self.ensure_loaded()
        return cve_id.upper() in self._data

    def get(self, cve_id: str) -> Optional[KEVEntry]:
        self.ensure_loaded()
        return self._data.get(cve_id.upper())

    def get_many(self, cve_ids: list[str]) -> dict[str, Optional[KEVEntry]]:
        self.ensure_loaded()
        return {cid: self._data.get(cid.upper()) for cid in cve_ids}

    def size(self) -> int:
        return len(self._data)


_kev_singleton: Optional[KEVCache] = None


def get_kev_cache() -> KEVCache:
    global _kev_singleton
    if _kev_singleton is None:
        _kev_singleton = KEVCache()
    return _kev_singleton


def lookup_kev(cve_ids: list[str], allow_network: bool = True) -> dict[str, Optional[KEVEntry]]:
    cache = get_kev_cache()
    try:
        cache.ensure_loaded(allow_download=allow_network)
    except Exception as e:
        logger.warning("KEV cache load failed: %s", e)
    return cache.get_many(cve_ids)
