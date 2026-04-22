"""
VAEL – Stage 1 / OSV Fetcher
Queries OSV.dev (Open Source Vulnerabilities) REST API.

Docs: https://google.github.io/osv.dev/api/
Great for: npm, PyPI, Go, Maven, RubyGems, Linux distros.
"""

from __future__ import annotations

import logging
from typing import Optional
import httpx

from schemas.stage1 import CVERecord, CVSSv3, CWEEntry, Reference, Severity

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{osv_id}"


ECOSYSTEM_GUESSES: dict[str, list[str]] = {
    # Maps common software names to likely OSV ecosystems
    "log4j":       ["Maven"],
    "spring":      ["Maven"],
    "django":      ["PyPI"],
    "flask":       ["PyPI"],
    "requests":    ["PyPI"],
    "numpy":       ["PyPI"],
    "express":     ["npm"],
    "lodash":      ["npm"],
    "nginx":       [""],          # OSV has limited nginx data
    "openssl":     [""],
    "wordpress":   [""],
}


def _guess_ecosystems(software: str) -> list[str]:
    key = software.lower().split("/")[-1]  # handle "org.apache/log4j" style
    return ECOSYSTEM_GUESSES.get(key, ["PyPI", "npm", "Maven"])


def _severity_from_score(score: Optional[float]) -> Severity:
    if score is None: return Severity.UNKNOWN
    if score >= 9.0:  return Severity.CRITICAL
    if score >= 7.0:  return Severity.HIGH
    if score >= 4.0:  return Severity.MEDIUM
    if score > 0.0:   return Severity.LOW
    return Severity.NONE


def _parse_osv_cvss(severity_list: list) -> Optional[CVSSv3]:
    for s in severity_list:
        if s.get("type") == "CVSS_V3":
            vector = s.get("score", "")
            # Extract base score from vector string if present
            score = None
            try:
                # CVSSv3 vector: CVSS:3.1/AV:N/... — score in "score" field or separate
                if isinstance(s.get("score"), (int, float)):
                    score = float(s["score"])
            except (ValueError, TypeError):
                pass
            return CVSSv3(
                score=score,
                vector=vector,
                severity=_severity_from_score(score),
            )
    return None


def _osv_item_to_cve_record(vuln: dict, target_version: str) -> CVERecord:
    osv_id = vuln.get("id", "UNKNOWN")

    # Map OSV IDs to CVE IDs if available
    cve_id = osv_id
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if alias.startswith("CVE-"):
            cve_id = alias
            break

    description = vuln.get("details") or vuln.get("summary") or ""

    # References
    refs = [
        Reference(url=r.get("url", ""), type=r.get("type"))
        for r in vuln.get("references", [])
        if r.get("url")
    ]

    # CWEs from database_specific
    cwes = []
    db_specific = vuln.get("database_specific", {})
    for cwe in db_specific.get("cwe_ids", []):
        cwes.append(CWEEntry(cwe_id=cwe))

    # Version affected — check if target_version is in any affected range
    version_matched = False
    affected_versions_raw = []
    for affected in vuln.get("affected", []):
        for version_info in affected.get("versions", []):
            affected_versions_raw.append(str(version_info))
            if str(version_info) == target_version:
                version_matched = True
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "introduced" in event or "fixed" in event:
                    # Simple: mark matched if version appears in events
                    if target_version in str(event.get("introduced", "")):
                        version_matched = True

    cvss = _parse_osv_cvss(vuln.get("severity", []))

    return CVERecord(
        cve_id=cve_id,
        source="OSV",
        description=description[:1000] if description else None,
        published=vuln.get("published"),
        last_modified=vuln.get("modified"),
        cvss_v3=cvss,
        cwes=cwes,
        references=refs,
        affected_versions_raw=affected_versions_raw[:20],
        version_matched=version_matched,
    )


def fetch_osv(
    software: str,
    version: str,
    ecosystem: Optional[str] = None,
    max_results: int = 100,
) -> tuple[list[CVERecord], list[str]]:
    """
    Query OSV.dev for vulnerabilities matching software + version.
    Tries multiple ecosystems if `ecosystem` not specified.

    Returns (cve_records, errors).
    """
    ecosystems = [ecosystem] if ecosystem else _guess_ecosystems(software)
    seen_ids: set[str] = set()
    cve_records: list[CVERecord] = []
    errors: list[str] = []

    with httpx.Client(timeout=20) as client:
        for eco in ecosystems:
            payload: dict = {
                "version": version,
                "package": {"name": software},
            }
            if eco:
                payload["package"]["ecosystem"] = eco

            try:
                resp = client.post(OSV_QUERY_URL, json=payload)
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                errors.append(f"OSV HTTP error ({eco}): {e}")
                continue
            except httpx.RequestError as e:
                errors.append(f"OSV request error ({eco}): {e}")
                continue

            vulns = resp.json().get("vulns", [])
            for vuln in vulns[:max_results]:
                vid = vuln.get("id", "")
                if vid in seen_ids:
                    continue
                seen_ids.add(vid)
                record = _osv_item_to_cve_record(vuln, version)
                cve_records.append(record)

    logger.info("OSV: fetched %d unique vulns for %s %s", len(cve_records), software, version)
    return cve_records, errors
