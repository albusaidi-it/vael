"""
VAEL – Stage 2 / EPSS Fetcher
Exploit Prediction Scoring System from FIRST.org

Strategy:
  - Daily CSV feed (~200 k CVEs) is downloaded once and imported into SQLite.
  - Lookups are indexed SQL queries — no loading 200 k rows into RAM.
  - Feed is refreshed automatically when older than 24 h.
  - Falls back to REST API for single-CVE lookup if the feed is unavailable.

Feed URL: https://epss.cyentia.com/epss_scores-current.csv.gz
API URL:  https://api.first.org/data/v1/epss?cve={id}
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
from datetime import date
from typing import Optional

from core import http_client
from core import cache as _db
from schemas.stage2 import EPSSEntry

logger = logging.getLogger(__name__)

EPSS_CSV_URL  = "https://epss.cyentia.com/epss_scores-current.csv.gz"
EPSS_API_URL  = "https://api.first.org/data/v1/epss"
_FEED_NAME    = "epss"
_TTL_SECONDS  = 24 * 3600


def _refresh(allow_download: bool = True) -> bool:
    """Download the EPSS CSV and import it into SQLite. Returns True on success."""
    if not allow_download:
        return False
    logger.info("Downloading EPSS feed")
    try:
        resp = http_client.api.get(EPSS_CSV_URL, timeout=60)
        resp.raise_for_status()
        text = gzip.decompress(resp.content).decode("utf-8")
    except Exception as e:
        logger.error("EPSS download failed: %s", e)
        return False

    rows: list[tuple] = []
    score_date: Optional[str] = None

    for line in text.splitlines():
        if line.startswith("#"):
            if "score_date:" in line:
                score_date = line.split("score_date:")[-1].strip().split("T")[0]
            continue
        break  # header line is next — hand off to csv reader

    reader = csv.DictReader(io.StringIO(text.lstrip("#\n")))
    for row in reader:
        cve_id = row.get("cve", "").strip().upper()
        if not cve_id:
            continue
        try:
            rows.append((
                cve_id,
                float(row.get("epss", 0)),
                float(row.get("percentile", 0)),
                score_date,
            ))
        except ValueError:
            continue

    if not rows:
        logger.warning("EPSS feed parsed 0 rows — keeping existing data")
        return False

    _db.epss_upsert_batch(rows)
    _db.feed_mark_updated(_FEED_NAME, len(rows), {"score_date": score_date})
    logger.info("EPSS feed imported: %d rows (score_date=%s)", len(rows), score_date)
    return True


def _ensure_current(allow_network: bool = True) -> None:
    if _db.feed_is_stale(_FEED_NAME, _TTL_SECONDS):
        _refresh(allow_download=allow_network)


def get_epss_score_date() -> Optional[date]:
    """Return the date of the currently stored EPSS feed, or None."""
    meta = _db.feed_get_meta(_FEED_NAME)
    raw = meta.get("score_date")
    if not raw:
        return None
    try:
        return date.fromisoformat(raw)
    except ValueError:
        return None


def _api_fallback(cve_id: str) -> Optional[EPSSEntry]:
    """Single-CVE lookup via FIRST.org REST API (used when feed is empty)."""
    try:
        resp = http_client.api.get(EPSS_API_URL, params={"cve": cve_id}, timeout=15)
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


def lookup_epss(cve_ids: list[str], allow_network: bool = True) -> dict[str, Optional[EPSSEntry]]:
    """
    Lookup EPSS scores for a list of CVE IDs.
    Refreshes the feed from FIRST.org when stale (>24 h).
    Falls back to the REST API for any CVEs still missing after the feed lookup.
    """
    _ensure_current(allow_network)

    raw = _db.epss_lookup_many(cve_ids)
    results: dict[str, Optional[EPSSEntry]] = {}
    missing: list[str] = []

    for cve_id, row in raw.items():
        if row:
            sd = row.get("score_date")
            results[cve_id] = EPSSEntry(
                cve_id=row["cve_id"],
                epss=row["epss"],
                percentile=row["percentile"],
                score_date=date.fromisoformat(sd) if sd else None,
            )
        else:
            results[cve_id] = None
            missing.append(cve_id)

    if allow_network:
        for cve_id in missing[:10]:
            results[cve_id] = _api_fallback(cve_id)

    return results
