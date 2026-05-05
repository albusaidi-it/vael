"""
VAEL – Stage 1 / GHSA Fetcher
GitHub Security Advisory Database via the GitHub GraphQL API.

Advantages over NVD:
  - Often published days before NVD
  - PURL-based ecosystem matching (more accurate for libraries than CPE)
  - Rich patch version data (first_patched_version per affected range)
  - Covers: npm, PyPI, Maven, Go, RubyGems, Rust, NuGet, Hex, Pub, Swift

No API key required for public advisories (60 req/hr unauthenticated).
Set GITHUB_TOKEN for 5000 req/hr and access to private org advisories.

GraphQL endpoint: https://api.github.com/graphql
"""

from __future__ import annotations

import logging
import random as _random
import re
from datetime import datetime
from typing import Optional

import httpx
from core import http_client

from schemas.stage1 import CVERecord, CVSSv3, CWEEntry, Reference, Severity
from core.config import settings
from core import cache as _cache
from core.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)

GHSA_GRAPHQL = "https://api.github.com/graphql"
_TTL = int(12 * 3600 * (0.9 + _random.random() * 0.2))  # 10.8–13.2 h jitter

_GHSA_QUERY = """
query($query: String!, $first: Int!, $after: String) {
  securityVulnerabilities(query: $query, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        description
        publishedAt
        updatedAt
        severity
        cvss { score vectorString }
        cwes(first: 5) { nodes { cweId name } }
        identifiers { type value }
        references { url }
      }
      package { ecosystem name }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}
"""

# GHSA severity → our Severity enum
_SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _cache_load(software: str, ecosystem: str):
    key  = _cache.make_key("ghsa", software, ecosystem)
    data = _cache.get(key)
    if data is None:
        return None
    try:
        return [CVERecord.model_validate(r) for r in data["cves"]], data.get("errors", [])
    except Exception:
        return None


def _cache_save(software: str, ecosystem: str, cves: list[CVERecord], errors: list[str]) -> None:
    key = _cache.make_key("ghsa", software, ecosystem)
    _cache.set(key, "ghsa", {"cves": [r.model_dump(mode="json") for r in cves], "errors": errors}, _TTL)


def _parse_node(node: dict, target_version: str) -> Optional[CVERecord]:
    advisory = node.get("advisory", {})
    pkg      = node.get("package", {})

    # Prefer CVE ID from identifiers list; fall back to GHSA ID
    cve_id = advisory.get("ghsaId", "UNKNOWN")
    for ident in advisory.get("identifiers", []):
        if ident.get("type") == "CVE":
            cve_id = ident["value"]
            break

    # CVSS
    cvss_raw = advisory.get("cvss") or {}
    score    = cvss_raw.get("score")
    vector   = cvss_raw.get("vectorString")
    sev_str  = advisory.get("severity", "")
    severity = _SEV_MAP.get(sev_str, Severity.UNKNOWN)
    cvss_v3  = CVSSv3(score=score, vector=vector, severity=severity) if score else None

    # CWEs
    cwes = [
        CWEEntry(cwe_id=c["cweId"], name=c.get("name"))
        for c in (advisory.get("cwes") or {}).get("nodes", [])
        if c.get("cweId")
    ]

    # References
    refs = [
        Reference(url=r["url"])
        for r in advisory.get("references", [])
        if r.get("url")
    ]

    # Version matching
    vuln_range = node.get("vulnerableVersionRange", "") or ""
    patched    = (node.get("firstPatchedVersion") or {}).get("identifier", "")

    version_matched = _version_in_range(target_version, vuln_range)

    # Patch info stored in references as a synthetic entry
    patch_refs: list[Reference] = []
    if patched:
        patch_refs.append(Reference(url=f"ghsa:patch:{patched}", tags=["patch", "fix"]))

    description = advisory.get("description") or advisory.get("summary") or ""

    return CVERecord(
        cve_id=cve_id,
        source="GHSA",
        description=description[:1000] if description else None,
        published=_parse_dt(advisory.get("publishedAt")),
        last_modified=_parse_dt(advisory.get("updatedAt")),
        cvss_v3=cvss_v3,
        cwes=cwes,
        references=refs + patch_refs,
        affected_versions_raw=[vuln_range] if vuln_range else [],
        version_matched=version_matched,
    )


def _version_in_range(version: str, range_str: str) -> bool:
    """
    Basic GHSA version range check.
    Range format: ">= 1.0, < 2.0"  or  "= 2.14.1"  or  ">= 2.0"
    """
    if not version or not range_str:
        return False
    try:
        from packaging.version import Version, InvalidVersion
        try:
            v = Version(version)
        except InvalidVersion:
            return False

        for part in range_str.split(","):
            part = part.strip()
            m = re.match(r"([><=!]+)\s*([^\s]+)", part)
            if not m:
                continue
            op, bound_str = m.group(1), m.group(2)
            try:
                bound = Version(bound_str)
            except InvalidVersion:
                continue
            checks = {
                ">=": v >= bound, ">": v > bound,
                "<=": v <= bound, "<": v < bound,
                "=": v == bound, "==": v == bound,
            }
            if not checks.get(op, True):
                return False
        return True
    except Exception:
        return version in range_str


def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_ghsa(
    software: str,
    version: str,
    ecosystem: Optional[str] = None,
    max_results: int = 100,
) -> tuple[list[CVERecord], list[str]]:
    """
    Fetch GHSA advisories for a software package.
    Returns (cve_records, errors).
    Skips silently if no GitHub token (uses 60 req/hr anonymous limit).
    """
    eco = (ecosystem or "").upper()
    cached = _cache_load(software, eco)
    if cached is not None:
        logger.info("GHSA cache hit for %s %s (%d CVEs)", software, eco, len(cached[0]))
        return cached

    token = settings.github_token
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Build search query — GHSA accepts "ecosystem:MAVEN package:log4j-core"
    query_parts = []
    if eco:
        query_parts.append(f"ecosystem:{eco}")
    # Use package name (last segment for Maven: "org.foo:bar" → "bar")
    pkg_name = software.split(":")[-1].split("/")[-1]
    query_parts.append(pkg_name)
    query_str = " ".join(query_parts)

    cve_records: list[CVERecord] = []
    errors: list[str] = []
    seen_ids: set[str] = set()
    after: Optional[str] = None
    fetched = 0

    has_token = bool(token)
    client = http_client.api
    while True:
        warn = rate_limiter.warn_and_log("ghsa", has_token)
        if warn:
            errors.append(f"[RateLimit] {warn}")

        variables = {"query": query_str, "first": min(100, max_results - fetched)}
        if after:
            variables["after"] = after

        try:
            resp = client.post(
                GHSA_GRAPHQL,
                json={"query": _GHSA_QUERY, "variables": variables},
                headers=headers,
                timeout=20,
            )
            rate_limiter.record("ghsa", dict(resp.headers), resp.status_code)
            if resp.status_code == 401:
                logger.warning("GHSA: authentication failed (bad token?)")
                errors.append("GHSA: 401 Unauthorized")
                break
            if resp.status_code in (403, 429):
                tip = "" if has_token else " Set GITHUB_TOKEN for 83x higher GHSA limit."
                errors.append(f"[RateLimit] GHSA rate limit hit.{tip}")
                break
            resp.raise_for_status()
        except httpx.RequestError as e:
            errors.append(f"GHSA request error: {e}")
            break

        data = resp.json()
        if "errors" in data:
            for err in data["errors"]:
                errors.append(f"GHSA GraphQL error: {err.get('message', err)}")
            break

        vuln_data = (data.get("data") or {}).get("securityVulnerabilities", {})
        nodes     = vuln_data.get("nodes", [])
        page_info = vuln_data.get("pageInfo", {})

        for node in nodes:
            record = _parse_node(node, version)
            if record and record.cve_id not in seen_ids:
                seen_ids.add(record.cve_id)
                cve_records.append(record)
                fetched += 1
                if fetched >= max_results:
                    break

        if fetched >= max_results or not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")

    logger.info("GHSA: fetched %d advisories for %s %s", len(cve_records), software, eco)
    _cache_save(software, eco, cve_records, errors)
    return cve_records, errors
