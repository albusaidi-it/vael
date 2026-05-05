"""
VAEL – VulnCheck Threat Intelligence Fetcher
Free community API (register at https://vulncheck.com/register).

Endpoints used:
  GET /v3/index/initial-access?cve={id}   → APT / threat actor associations
  GET /v3/index/ransomware?cve={id}        → ransomware group associations

Both return 404 when no data exists — that is normal (most CVEs have none).
Set VULNCHECK_API_KEY in your environment to enable.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx
from core import http_client

from schemas.stage2 import ThreatIntel
from core.config import settings
from core import cache as _cache
from core.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

VULNCHECK_BASE = "https://api.vulncheck.com/v3/index"
_TTL = 48 * 3600   # 48 hours


def _api_key() -> Optional[str]:
    return settings.vulncheck_api_key


def _cache_load(cve_id: str) -> Optional[ThreatIntel]:
    key  = _cache.make_key("vulncheck", cve_id.upper())
    data = _cache.get(key)
    if data is None:
        return None
    try:
        return ThreatIntel.model_validate(data)
    except Exception:
        return None


def _cache_save(cve_id: str, intel: ThreatIntel) -> None:
    key = _cache.make_key("vulncheck", cve_id.upper())
    _cache.set(key, "vulncheck", intel.model_dump(mode="json"), _TTL)


def _get(client: httpx.Client, endpoint: str, cve_id: str, token: str) -> Optional[list[dict]]:
    """GET one VulnCheck index endpoint. Returns the `data` list or None."""
    warn = rate_limiter.warn_and_log("vulncheck", has_key=True)
    if warn:
        logger.warning("[RateLimit] %s", warn)
    try:
        resp = client.get(
            f"{VULNCHECK_BASE}/{endpoint}",
            params={"cve": cve_id},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        rate_limiter.record("vulncheck", dict(resp.headers), resp.status_code)
        if resp.status_code == 404:
            return []          # no data — normal
        if resp.status_code == 401:
            logger.warning("VulnCheck: invalid or missing API key")
            return None
        if resp.status_code == 429:
            logger.warning("VulnCheck: rate limit hit for %s/%s", endpoint, cve_id)
            return None
        resp.raise_for_status()
        return resp.json().get("data") or []
    except httpx.RequestError as e:
        logger.debug("VulnCheck request error (%s): %s", endpoint, e)
        return None


def fetch_threat_intel(cve_id: str) -> ThreatIntel:
    """
    Fetch threat intelligence for a CVE from VulnCheck.
    Returns a ThreatIntel object — empty (no actors/groups) if no API key
    is set or if VulnCheck has no data for this CVE.
    """
    token = _api_key()
    if not token:
        return ThreatIntel()

    cached = _cache_load(cve_id)
    if cached is not None:
        return cached

    threat_actors: list[str] = []
    ransomware_groups: list[str] = []
    exploitation_notes: list[str] = []
    in_the_wild = False

    client = http_client.api

    # ── Initial access / APT associations ───────────────────────────────
    ia_data = _get(client, "initial-access", cve_id, token)
    if ia_data:
        for entry in ia_data:
            actor = entry.get("threat_actor") or entry.get("actor") or entry.get("name")
            if actor and actor not in threat_actors:
                threat_actors.append(actor)
        if threat_actors:
            in_the_wild = True
            exploitation_notes.append(
                f"Used by {len(threat_actors)} threat actor(s): {', '.join(threat_actors[:3])}"
            )

    # ── Ransomware associations ──────────────────────────────────────────
    rw_data = _get(client, "ransomware", cve_id, token)
    if rw_data:
        for entry in rw_data:
            group = entry.get("name") or entry.get("group") or entry.get("threat_actor")
            if group and group not in ransomware_groups:
                ransomware_groups.append(group)
        if ransomware_groups:
            in_the_wild = True
            exploitation_notes.append(
                f"Linked to {len(ransomware_groups)} ransomware group(s): "
                f"{', '.join(ransomware_groups[:3])}"
            )

    intel = ThreatIntel(
        threat_actors=threat_actors,
        ransomware_groups=ransomware_groups,
        in_the_wild=in_the_wild,
        exploitation_notes=exploitation_notes,
    )
    _cache_save(cve_id, intel)
    return intel
