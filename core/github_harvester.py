"""
VAEL – Stage 3 / GitHub Harvester
Searches GitHub for CVE PoC repositories.

Challenges:
  - GitHub search for famous CVEs returns 100s of repos, most of which are:
    - Empty reposts / "awesome" lists / blog clones
    - Forks with no added value
    - Fake repos (especially for Log4Shell, Spring4Shell, etc.)
  - Rate limit: 10 req/min unauthenticated, 30 req/min authenticated
  - No native version-compatibility check — must parse README

Strategy:
  1. Search for `"CVE-YYYY-NNNNN" in:name OR in:description OR in:readme`
  2. Score repos by: stars, has_code, README length, authored by known security researchers
  3. Fetch README of top-N candidates for version analysis
  4. Classify quality via heuristics
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime, date
from typing import Optional
import httpx
from core import http_client
from core import cache as _cache

from schemas.stage3 import (
    PoCRecord, PoCSource, PoCQuality, VersionCompatibility,
)
from core.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
GITHUB_README_URL = "https://api.github.com/repos/{owner}/{repo}/readme"
RATE_LIMIT_DELAY  = 2.0   # seconds between calls without auth token


# ── Known high-signal security researchers / orgs ─────────────────────
# PoCs by these authors are more likely to be legitimate
TRUSTED_AUTHORS = {
    "rapid7", "metasploit", "projectdiscovery", "nuclei-templates",
    "kaonashi-peqrx", "tin-z", "mbadanoiu", "offensive-security",
    "sanrocker", "pentest-tools-com", "0xricksanchez", "sighook",
    "apache", "oracle", "microsoft",
}

# ── Known spam / fake PoC patterns ────────────────────────────────────
FAKE_REPO_PATTERNS = [
    re.compile(r"^(awesome|list|collection|blog|writeup)s?[-_]?", re.I),
    re.compile(r"(walkthrough|tutorial|explained)$", re.I),
    # Note: "^cve-YYYY-NNNNN$" repos are intentionally NOT blocked —
    # many legitimate single-CVE PoCs use this exact naming convention.
]

# Files that indicate executable PoC code
EXPLOIT_FILE_PATTERNS = [
    re.compile(r"\.(py|rb|sh|pl|c|cpp|go|js|ts|java)$", re.I),
    re.compile(r"^exploit", re.I),
    re.compile(r"^poc", re.I),
    re.compile(r"\.yaml$", re.I),   # Nuclei templates
]


def _is_likely_fake(repo_name: str, description: Optional[str], stars: int = 0) -> bool:
    """Heuristic check for fake/spam repos."""
    name_lower = repo_name.lower()

    # Empty description is only suspicious if the repo also has no stars
    if (description is None or len(description) < 15) and stars == 0:
        return True

    for pat in FAKE_REPO_PATTERNS:
        if pat.search(repo_name):
            return True

    # Obvious click-bait indicators
    clickbait = ["free", "full", "download", "crack", "unlimited"]
    if any(c in name_lower for c in clickbait):
        return True

    return False


def _detect_language(repo: dict) -> Optional[str]:
    lang = repo.get("language")
    return lang.lower() if lang else None


def _classify_quality(
    repo: dict,
    has_readme: bool,
    readme_text: str,
) -> PoCQuality:
    """Classify the quality of a PoC repo based on signals."""
    name    = repo.get("name", "")
    desc    = repo.get("description", "") or ""
    stars   = repo.get("stargazers_count", 0)
    owner   = (repo.get("owner", {}) or {}).get("login", "").lower()
    size_kb = repo.get("size", 0)

    if _is_likely_fake(name, desc, stars=stars):
        return PoCQuality.FAKE

    # Trusted author is strong signal
    if owner in TRUSTED_AUTHORS:
        return PoCQuality.WEAPONIZED

    # Nuclei template / Metasploit module detection
    name_desc = (name + " " + desc).lower()
    if any(k in name_desc for k in ["nuclei", "metasploit", "msf-module"]):
        return PoCQuality.WEAPONIZED

    # Readme + code + non-trivial size → functional
    has_exploit_keywords = bool(re.search(
        r"\b(exploit|payload|rce|shell|reverse|bind|jndi|ssrf)\b",
        readme_text.lower()
    ))

    if has_readme and size_kb > 5 and has_exploit_keywords:
        if stars >= 20:
            return PoCQuality.FUNCTIONAL
        return PoCQuality.CONCEPTUAL

    # Low signal: has readme but not much else
    if has_readme:
        return PoCQuality.CONCEPTUAL

    return PoCQuality.UNKNOWN


def _check_version_compatibility(
    target_version: str,
    readme_text: str,
    repo_desc: str,
) -> tuple[VersionCompatibility, list[str]]:
    """
    Static analysis: look for version strings in README / description
    to determine if this PoC targets the same version.
    """
    text = (readme_text + " " + repo_desc).lower()
    target = target_version.strip().lower()

    # Find all version-like strings in the text
    version_pattern = re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[-.][a-z0-9]+)?)\b")
    detected = list(set(version_pattern.findall(text)))

    # Confirmed: target version appears verbatim
    if target in text:
        return VersionCompatibility.CONFIRMED, detected[:10]

    # Check version ranges
    # Look for patterns like "affects versions X.Y.Z - A.B.C" or "< X.Y.Z"
    range_patterns = [
        r"affects?\s+versions?\s+(\S+)\s*(?:to|-|through|–)\s*(\S+)",
        r"version\s+(\S+)\s*-\s*(\S+)",
        r"<=?\s*(\d+\.\d+(?:\.\d+)?)",
    ]
    for pat in range_patterns:
        m = re.search(pat, text)
        if m:
            return VersionCompatibility.LIKELY, detected[:10]

    if detected:
        # Some version info exists but not our target — weak signal
        # Don't claim INCOMPATIBLE unless we're sure
        return VersionCompatibility.UNKNOWN, detected[:10]

    return VersionCompatibility.UNKNOWN, []


def _fetch_readme(
    client: httpx.Client,
    owner: str,
    repo: str,
    headers: dict,
) -> str:
    """Fetch README content (base64-decoded). Returns empty on failure."""
    try:
        url = GITHUB_README_URL.format(owner=owner, repo=repo)
        resp = client.get(url, headers=headers, timeout=15)
        rate_limiter.record("github", dict(resp.headers), resp.status_code)
        if resp.status_code in (403, 429):
            logger.warning("GitHub REST rate limit hit fetching README for %s/%s", owner, repo)
            return ""
        if resp.status_code != 200:
            return ""
        data = resp.json()
        import base64
        content_b64 = data.get("content", "")
        if not content_b64:
            return ""
        decoded = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
        return decoded[:10000]   # Cap size
    except Exception as e:
        logger.debug("README fetch failed for %s/%s: %s", owner, repo, e)
        return ""


_GITHUB_CACHE_TTL = 6 * 3600   # 6 hours


def _cache_load(cve_id: str) -> Optional[list[PoCRecord]]:
    key  = _cache.make_key("github_pocs", cve_id.upper())
    data = _cache.get(key)
    if data is None:
        return None
    try:
        return [PoCRecord.model_validate(r) for r in data]
    except Exception:
        return None


def _cache_save(cve_id: str, pocs: list[PoCRecord]) -> None:
    key = _cache.make_key("github_pocs", cve_id.upper())
    _cache.set(key, "github_pocs", [p.model_dump(mode="json") for p in pocs], _GITHUB_CACHE_TTL)


def search_github(
    cve_id: str,
    target_version: str,
    github_token: Optional[str] = None,
    max_repos: int = 15,
    deep_analyze: int = 8,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Search GitHub for PoCs of a specific CVE.

    Args:
        cve_id:         CVE ID to search for (e.g. "CVE-2021-44228")
        target_version: Target software version for compatibility checks
        github_token:   Optional auth token for higher rate limits
        max_repos:      Maximum repos to return metadata for
        deep_analyze:   Number of top repos to fetch full README for

    Returns:
        (poc_records, errors)
    """
    headers = {"Accept": "application/vnd.github+json"}
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    # Query: name + description + readme — most comprehensive
    params = {
        "q": f'"{cve_id}" in:name,description,readme',
        "sort": "stars",
        "order": "desc",
        "per_page": min(max_repos, 30),
    }

    cached = _cache_load(cve_id)
    if cached is not None:
        logger.info("GitHub cache hit: %d PoCs for %s", len(cached), cve_id)
        return cached, []

    pocs: list[PoCRecord] = []
    errors: list[str] = []

    has_token = bool(github_token)
    client = http_client.api
    # ── 1. Search ─────────────────────────────────────────────────
    # Pre-flight check
    warn = rate_limiter.warn_and_log("github_search", has_token)
    if warn:
        errors.append(f"[RateLimit] {warn}")

    try:
        resp = client.get(GITHUB_SEARCH_URL, params=params, headers=headers, timeout=20)
        rate_limiter.record("github_search", dict(resp.headers), resp.status_code)
        if resp.status_code in (403, 429):
            tip = "" if has_token else " Set GITHUB_TOKEN to get 30 req/min instead of 10."
            errors.append(
                f"[RateLimit] GitHub search rate limit hit for {cve_id}.{tip} "
                f"Retry after {resp.headers.get('retry-after', 'unknown')}s."
            )
            return pocs, errors
        resp.raise_for_status()
    except httpx.HTTPError as e:
        errors.append(f"GitHub search error for {cve_id}: {e}")
        return pocs, errors

    items = resp.json().get("items", [])[:max_repos]
    if not github_token:
        time.sleep(RATE_LIMIT_DELAY)

    # ── 2. Per-repo analysis ──────────────────────────────────────
    for i, repo in enumerate(items):
        owner = (repo.get("owner", {}) or {}).get("login", "")
        name  = repo.get("name", "")
        url   = repo.get("html_url", "")
        desc  = repo.get("description") or ""

        # Fetch README only for top candidates (expensive)
        readme_text = ""
        has_readme = False
        if i < deep_analyze:
            readme_text = _fetch_readme(client, owner, name, headers)
            has_readme  = bool(readme_text)
            if not github_token:
                time.sleep(RATE_LIMIT_DELAY)

        quality = _classify_quality(repo, has_readme, readme_text)
        compat, detected_versions = _check_version_compatibility(
            target_version, readme_text, desc
        )

        # Extract publish date
        pub = None
        if repo.get("created_at"):
            try:
                pub = date.fromisoformat(repo["created_at"].split("T")[0])
            except ValueError:
                pass

        pocs.append(PoCRecord(
            cve_id=cve_id,
            source=PoCSource.GITHUB,
            url=url,
            title=f"{owner}/{name}",
            author=owner,
            published=pub,
            stars=repo.get("stargazers_count"),
            forks=repo.get("forks_count"),
            description=desc[:500] if desc else None,
            quality=quality,
            version_compatibility=compat,
            detected_versions=detected_versions,
            has_executable_code=repo.get("size", 0) > 5,   # size in KB
            has_readme=has_readme,
            language=_detect_language(repo),
            raw_meta={"size_kb": repo.get("size", 0)},
        ))

    logger.info("GitHub: %d PoCs found for %s", len(pocs), cve_id)
    if pocs:
        _cache_save(cve_id, pocs)
    return pocs, errors
