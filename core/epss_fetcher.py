"""
VAEL – Stage 2 / EPSS Fetcher
Exploit Prediction Scoring System from FIRST.org

Strategy:
  - Daily CSV feed (~200k CVEs) is downloaded ONCE and cached locally
  - All lookups are in-memory O(1) dict operations
  - Cache refreshed automatically if older than 24h
  - Falls back to REST API for single-CVE lookup if cache unavailable

Feed URL: https://epss.cyentia.com/epss_scores-current.csv.gz
API URL:  https://api.first.org/data/v1/epss?cve={id}
"""

from __future__ import annotations

import csv
import gzip
import logging
import os
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Optional
import httpx

from schemas.stage2 import EPSSEntry

logger = logging.getLogger(__name__)

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_CACHE_DIR = Path(os.environ.get("VAEL_CACHE_DIR", "./feeds"))
CACHE_TTL = timedelta(hours=24)


class EPSSCache:
    """In-memory EPSS score cache, backed by daily CSV download."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "epss_scores.csv"
        self._data: dict[str, EPSSEntry] = {}
        self._loaded = False
        self._score_date: Optional[date] = None

    def _cache_is_stale(self) -> bool:
        if not self.cache_file.exists():
            return True
        mtime = datetime.fromtimestamp(self.cache_file.stat().st_mtime)
        return (datetime.now() - mtime) > CACHE_TTL

    def _download_csv(self) -> bool:
        logger.info("Downloading EPSS feed from %s", EPSS_CSV_URL)
        try:
            with httpx.Client(timeout=60, follow_redirects=True) as client:
                resp = client.get(EPSS_CSV_URL)
                resp.raise_for_status()
            decompressed = gzip.decompress(resp.content).decode("utf-8")
            self.cache_file.write_text(decompressed, encoding="utf-8")
            logger.info("EPSS feed cached: %d bytes", len(decompressed))
            return True
        except Exception as e:
            logger.error("Failed to download EPSS feed: %s", e)
            return False

    def _parse_csv(self) -> None:
        """Load cached CSV into memory. Format:
           line 1: #model_version:... ,score_date:YYYY-MM-DDTHH:MM:SS+00:00
           line 2: cve,epss,percentile
           line 3+: data"""
        if not self.cache_file.exists():
            return
        try:
            with self.cache_file.open("r", encoding="utf-8") as f:
                score_date = None
                data_lines = []
                for line in f:
                    if line.startswith("#"):
                        if "score_date:" in line:
                            date_str = line.split("score_date:")[-1].strip().split("T")[0]
                            try:
                                score_date = date.fromisoformat(date_str)
                            except ValueError:
                                pass
                    else:
                        data_lines.append(line)

                self._score_date = score_date
                reader = csv.DictReader(data_lines)
                count = 0
                for row in reader:
                    try:
                        cve_id = row.get("cve", "").strip().upper()
                        if not cve_id:
                            continue
                        self._data[cve_id] = EPSSEntry(
                            cve_id=cve_id,
                            epss=float(row.get("epss", 0)),
                            percentile=float(row.get("percentile", 0)),
                            score_date=score_date,
                        )
                        count += 1
                    except (ValueError, KeyError):
                        continue
                logger.info("Loaded %d EPSS entries (score_date=%s)", count, score_date)
        except Exception as e:
            logger.error("Failed to parse EPSS CSV: %s", e)

    def ensure_loaded(self, allow_download: bool = True) -> None:
        if self._loaded and self._data:
            return
        if self._cache_is_stale() and allow_download:
            self._download_csv()
        self._parse_csv()
        self._loaded = True

    def get(self, cve_id: str) -> Optional[EPSSEntry]:
        self.ensure_loaded()
        return self._data.get(cve_id.upper())

    def get_many(self, cve_ids: list[str]) -> dict[str, Optional[EPSSEntry]]:
        self.ensure_loaded()
        return {cid: self._data.get(cid.upper()) for cid in cve_ids}

    def size(self) -> int:
        return len(self._data)


def fetch_epss_api(cve_id: str) -> Optional[EPSSEntry]:
    """Fallback single-CVE lookup via FIRST.org REST API."""
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(EPSS_API_URL, params={"cve": cve_id})
            resp.raise_for_status()
            data = resp.json().get("data", [])
            if not data:
                return None
            entry = data[0]
            return EPSSEntry(
                cve_id=entry.get("cve", cve_id),
                epss=float(entry.get("epss", 0)),
                percentile=float(entry.get("percentile", 0)),
                score_date=date.fromisoformat(entry["date"]) if entry.get("date") else None,
            )
    except Exception as e:
        logger.warning("EPSS API fallback failed for %s: %s", cve_id, e)
        return None


_cache_singleton: Optional[EPSSCache] = None


def get_epss_cache() -> EPSSCache:
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = EPSSCache()
    return _cache_singleton


def lookup_epss(cve_ids: list[str], allow_network: bool = True) -> dict[str, Optional[EPSSEntry]]:
    """Lookup EPSS entries for a list of CVEs. Uses cache + API fallback."""
    cache = get_epss_cache()
    try:
        cache.ensure_loaded(allow_download=allow_network)
    except Exception as e:
        logger.warning("EPSS cache load failed: %s", e)

    results = cache.get_many(cve_ids)

    if allow_network:
        missing = [cid for cid, v in results.items() if v is None]
        for cid in missing[:10]:
            results[cid] = fetch_epss_api(cid)

    return results
