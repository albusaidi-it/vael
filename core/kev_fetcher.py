"""
VAEL – Stage 2 / CISA KEV Fetcher
CISA Known Exploited Vulnerabilities catalog.

Strategy:
  - Full KEV catalog (~1 k entries) downloaded once and imported into SQLite.
  - Lookups are indexed SQL queries.
  - Feed refreshed automatically when older than 24 h.

Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

from __future__ import annotations

import json
import logging
from datetime import date
from typing import Optional

from core import http_client
from core import cache as _db
from schemas.stage2 import KEVEntry

logger = logging.getLogger(__name__)

KEV_URL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_FEED_NAME   = "kev"
_TTL_SECONDS = 24 * 3600


def _parse_date(s: Optional[str]) -> Optional[str]:
    """Normalise a date string to ISO format (YYYY-MM-DD), or None."""
    if not s:
        return None
    try:
        return date.fromisoformat(s.split("T")[0]).isoformat()
    except ValueError:
        return None


def _refresh(allow_download: bool = True) -> bool:
    """Download KEV JSON and import it into SQLite. Returns True on success."""
    if not allow_download:
        return False
    logger.info("Downloading CISA KEV catalog")
    try:
        resp = http_client.api.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        catalog = resp.json()
    except Exception as e:
        logger.error("KEV download failed: %s", e)
        return False

    rows: list[tuple] = []
    for v in catalog.get("vulnerabilities", []):
        cve_id = v.get("cveID", "").upper().strip()
        if not cve_id:
            continue
        rows.append((
            cve_id,
            v.get("vendorProject"),
            v.get("product"),
            v.get("vulnerabilityName"),
            _parse_date(v.get("dateAdded")),
            v.get("shortDescription"),
            v.get("requiredAction"),
            _parse_date(v.get("dueDate")),
            v.get("knownRansomwareCampaignUse"),
            v.get("notes"),
        ))

    if not rows:
        logger.warning("KEV feed parsed 0 rows — keeping existing data")
        return False

    _db.kev_upsert_batch(rows)
    _db.feed_mark_updated(_FEED_NAME, len(rows), {
        "catalog_version": catalog.get("catalogVersion"),
        "catalog_date":    catalog.get("dateReleased"),
    })
    logger.info("KEV feed imported: %d entries (v%s)",
                len(rows), catalog.get("catalogVersion"))
    return True


def _ensure_current(allow_network: bool = True) -> None:
    if _db.feed_is_stale(_FEED_NAME, _TTL_SECONDS):
        _refresh(allow_download=allow_network)


def _row_to_entry(row: dict) -> KEVEntry:
    def _d(s):
        try:
            return date.fromisoformat(s) if s else None
        except ValueError:
            return None
    return KEVEntry(
        cve_id=row["cve_id"],
        vendor_project=row.get("vendor_project"),
        product=row.get("product"),
        vulnerability_name=row.get("vulnerability_name"),
        date_added=_d(row.get("date_added")),
        short_description=row.get("short_description"),
        required_action=row.get("required_action"),
        due_date=_d(row.get("due_date")),
        known_ransomware_campaign_use=row.get("known_ransomware_campaign_use"),
        notes=row.get("notes"),
    )


def lookup_kev(
    cve_ids: list[str],
    allow_network: bool = True,
) -> dict[str, Optional[KEVEntry]]:
    """
    Lookup KEV entries for a list of CVE IDs.
    Refreshes the feed from CISA when stale (>24 h).
    """
    _ensure_current(allow_network)
    raw = _db.kev_lookup_many(cve_ids)
    return {
        cve_id: _row_to_entry(row) if row else None
        for cve_id, row in raw.items()
    }
