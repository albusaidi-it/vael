"""
VAEL – Rapid7 AttackerKB Fetcher (Stage 1)
Queries the AttackerKB community API for CVEs related to a software.

API: https://api.attackerkb.com/v1/topics
Auth: Bearer token (ATTACKERKB_API_KEY) — required; returns empty if missing.

AttackerKB topics are community exploitability assessments from Rapid7.
They complement NVD/OSV with exploitation status flags and attacker scores.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional

import httpx
from core import http_client

from core import cache as _cache_mod
from core.rate_limiter import rate_limiter
from core.utils import severity_from_score
from schemas.stage1 import CVERecord, CVSSv3, Severity, Reference

logger = logging.getLogger(__name__)

_BASE    = "https://api.attackerkb.com/v1"
_TTL     = 6 * 3600   # 6-hour cache
_CVE_RE  = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)



def _parse_topic(topic: dict) -> Optional[CVERecord]:
    """Convert one AttackerKB topic dict into a CVERecord, or None if not a CVE topic."""
    name = topic.get("name", "")
    if not _CVE_RE.match(name):
        return None

    cve_id = name.upper()
    doc    = topic.get("document") or {}
    meta   = topic.get("metadata") or {}

    description = doc.get("description") or doc.get("summary") or ""

    # CVSS from NVD score stored in AttackerKB metadata
    nvd_score  = meta.get("nvdScore") or meta.get("cvssV3BaseScore")
    nvd_vector = meta.get("nvdVector") or meta.get("cvssV3Vector")
    cvss_v3: Optional[CVSSv3] = None
    if nvd_score is not None:
        try:
            s = float(nvd_score)
            cvss_v3 = CVSSv3(score=s, vector=nvd_vector, severity=severity_from_score(s))
        except (ValueError, TypeError):
            pass

    # Published date
    published: Optional[datetime] = None
    for date_key in ("publishedDate", "cvePublished", "revisionDate"):
        raw = topic.get(date_key) or meta.get(date_key)
        if raw:
            try:
                published = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                break
            except (ValueError, AttributeError):
                pass

    # References from document
    refs: list[Reference] = []
    for ref in doc.get("references", []):
        if isinstance(ref, dict) and ref.get("url"):
            refs.append(Reference(url=ref["url"]))

    return CVERecord(
        cve_id=cve_id,
        source="ATTACKERKB",
        description=description,
        published=published,
        cvss_v3=cvss_v3,
        references=refs,
        version_matched=False,
    )


def fetch_attackerkb(
    software: str,
    version: str,
    api_key: Optional[str] = None,
    max_results: int = 50,
) -> tuple[list[CVERecord], list[str]]:
    """
    Search AttackerKB for CVEs related to `software`.

    Returns empty list if no ATTACKERKB_API_KEY is set (key is required by API).
    Results are cached for 6 hours to avoid hammering the rate limit.
    """
    if not api_key:
        return [], []

    cache_key = _cache_mod.make_key("attackerkb", software, max_results)
    cached = _cache_mod.get(cache_key)
    if cached is not None:
        return [CVERecord(**r) for r in cached], []

    records: list[CVERecord] = []
    errors:  list[str]       = []

    try:
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        }
        resp = http_client.api.get(
            f"{_BASE}/topics",
            params={"q": software, "size": min(max_results, 50)},
            headers=headers,
            timeout=20,
        )
        rate_limiter.record("attackerkb", dict(resp.headers), resp.status_code)

        if resp.status_code == 401:
            errors.append("AttackerKB: invalid API key (check ATTACKERKB_API_KEY)")
            return records, errors
        if resp.status_code == 429:
            errors.append(f"[RateLimit] AttackerKB rate-limited searching for {software}")
            return records, errors
        if not resp.is_success:
            errors.append(
                f"AttackerKB search failed (HTTP {resp.status_code}) for {software}"
            )
            return records, errors

        for topic in resp.json().get("data", []):
            rec = _parse_topic(topic)
            if rec:
                records.append(rec)

        logger.info("AttackerKB returned %d CVEs for %s", len(records), software)

    except Exception as e:
        errors.append(f"AttackerKB fetch error for {software}: {e}")
        return records, errors

    if records:
        _cache_mod.set(
            cache_key, "attackerkb",
            [r.model_dump(mode="json") for r in records],
            _TTL,
        )
    return records, errors
