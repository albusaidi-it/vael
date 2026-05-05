"""
VAEL – Metasploit Module Harvester
Searches the rapid7/metasploit-framework GitHub repository for modules
that target a given CVE. Metasploit modules are always WEAPONIZED quality —
they are production exploit tools with target/payload selection built in.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

import httpx
from core import http_client

from core import cache as _cache_mod
from core.rate_limiter import rate_limiter
from schemas.stage3 import PoCRecord, PoCSource, PoCQuality, VersionCompatibility

logger = logging.getLogger(__name__)

_MSF_REPO = "rapid7/metasploit-framework"
_SEARCH_URL = "https://api.github.com/search/code"
_RAW_BASE = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/"
_HEADERS_BASE = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
_TTL = 48 * 3600  # 48 h — MSF modules don't change often

_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def _module_title(name: str, path: str) -> str:
    """Human-readable title from module filename and path."""
    category = path.split("/")[1] if "/" in path else "module"
    human = name.replace(".rb", "").replace("_", " ").title()
    return f"Metasploit: {human} [{category}]"


def _check_module_version(path: str, target_version: str) -> tuple[VersionCompatibility, list[str]]:
    """
    Fetch the first 6 KB of the module source and scan for version strings.
    raw.githubusercontent.com is not subject to GitHub API rate limits.
    """
    try:
        resp = http_client.scrape.get(_RAW_BASE + path, timeout=10)
        if resp.status_code != 200:
            return VersionCompatibility.UNKNOWN, []
        content = resp.text[:6000]
        versions = list(set(_VERSION_RE.findall(content)))
        if target_version in content:
            return VersionCompatibility.CONFIRMED, versions[:10]
        if versions:
            return VersionCompatibility.LIKELY, versions[:10]
        return VersionCompatibility.UNKNOWN, []
    except Exception:
        return VersionCompatibility.UNKNOWN, []


def search_metasploit(
    cve_id: str,
    target_version: str,
    github_token: Optional[str] = None,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    cache_key = _cache_mod.make_key("metasploit", cve_id)
    cached = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []

    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str] = []

    headers = dict(_HEADERS_BASE)
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    has_token = bool(github_token)

    warn = rate_limiter.warn_and_log("github_search", has_token)
    if warn:
        errors.append(f"[RateLimit] {warn}")

    try:
        resp = http_client.api.get(
            _SEARCH_URL,
            params={"q": f"{cve_id} repo:{_MSF_REPO}", "per_page": 10},
            headers=headers,
            timeout=20,
        )
        rate_limiter.record("github_search", dict(resp.headers), resp.status_code)

        if resp.status_code == 403:
            errors.append(f"[RateLimit] GitHub Search rate-limited for Metasploit/{cve_id}")
            return pocs, errors
        if resp.status_code == 422:
            # GitHub rejects searches it can't process (e.g. very new CVEs with no indexed files)
            return pocs, errors
        if not resp.is_success:
            errors.append(f"Metasploit GitHub search failed ({resp.status_code}) for {cve_id}")
            return pocs, errors

        for item in resp.json().get("items", []):
            path     = item.get("path", "")
            html_url = item.get("html_url", "")
            name     = item.get("name", "")

            # Only Ruby module files under modules/
            if not (path.startswith("modules/") and path.endswith(".rb")):
                continue

            compat, detected_versions = _check_module_version(path, target_version)
            pocs.append(PoCRecord(
                cve_id=cve_id,
                source=PoCSource.METASPLOIT,
                url=html_url,
                title=_module_title(name, path),
                quality=PoCQuality.WEAPONIZED,
                version_compatibility=compat,
                detected_versions=detected_versions,
                has_executable_code=True,
                language="ruby",
            ))

    except Exception as e:
        errors.append(f"Metasploit search error for {cve_id}: {e}")
        return pocs, errors

    if pocs:
        _cache_mod.set(
            cache_key, "metasploit",
            [p.model_dump(mode="json") for p in pocs],
            _TTL,
        )
    return pocs, errors
