"""
VAEL – Stage 1 / NVD Fetcher
Queries the NVD API v2 for CVEs matching software + version.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 req/30s without API key, 50 req/30s with key.
"""

from __future__ import annotations

import logging
import time
from typing import Optional
import httpx

from schemas.stage1 import (
    CVERecord, CVSSv3, CVSSv2, CWEEntry, Reference, CPEMatch, Severity
)
from core.version_utils import version_in_range

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 100
RETRY_WAIT = 6          # seconds between retries on 403/503
MAX_RETRIES = 3


def _severity_from_score(score: Optional[float]) -> Severity:
    if score is None:
        return Severity.UNKNOWN
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


def _parse_cvss_v3(metrics: dict) -> Optional[CVSSv3]:
    """Extract best available CVSSv3 block (prefer cvssMetricV31 over V30)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            return CVSSv3(
                score=score,
                vector=data.get("vectorString"),
                severity=_severity_from_score(score),
                attack_vector=data.get("attackVector"),
                attack_complexity=data.get("attackComplexity"),
                privileges_required=data.get("privilegesRequired"),
                user_interaction=data.get("userInteraction"),
                confidentiality_impact=data.get("confidentialityImpact"),
                integrity_impact=data.get("integrityImpact"),
                availability_impact=data.get("availabilityImpact"),
            )
    return None


def _parse_cvss_v2(metrics: dict) -> Optional[CVSSv2]:
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        data = entries[0].get("cvssData", {})
        score = data.get("baseScore")
        return CVSSv2(
            score=score,
            vector=data.get("vectorString"),
            severity=_severity_from_score(score),
        )
    return None


def _parse_cwes(weaknesses: list) -> list[CWEEntry]:
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(CWEEntry(cwe_id=val))
    return cwes


def _parse_references(refs: list) -> list[Reference]:
    return [
        Reference(
            url=r.get("url", ""),
            source=r.get("source"),
            tags=r.get("tags", []),
        )
        for r in refs
        if r.get("url")
    ]


def _parse_cpe_matches(configurations: list) -> list[CPEMatch]:
    matches = []
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable", False):
                    matches.append(CPEMatch(
                        cpe23=match.get("criteria", ""),
                        version_start_including=match.get("versionStartIncluding"),
                        version_end_excluding=match.get("versionEndExcluding"),
                        version_end_including=match.get("versionEndIncluding"),
                        vulnerable=True,
                    ))
    return matches


def _nvd_item_to_cve_record(item: dict, target_version: str) -> CVERecord:
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "UNKNOWN")

    # Description (prefer English)
    description = ""
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    metrics = cve_data.get("metrics", {})
    configurations = cve_data.get("configurations", [])

    cpe_matches = _parse_cpe_matches(configurations)

    # Check version match
    version_matched = any(
        version_in_range(target_version, m) for m in cpe_matches
    )

    return CVERecord(
        cve_id=cve_id,
        source="NVD",
        description=description,
        published=cve_data.get("published"),
        last_modified=cve_data.get("lastModified"),
        cvss_v3=_parse_cvss_v3(metrics),
        cvss_v2=_parse_cvss_v2(metrics),
        cwes=_parse_cwes(cve_data.get("weaknesses", [])),
        references=_parse_references(cve_data.get("references", [])),
        cpe_matches=cpe_matches,
        version_matched=version_matched,
    )


def fetch_nvd(
    software: str,
    version: str,
    api_key: Optional[str] = None,
    max_results: int = 200,
) -> tuple[list[CVERecord], list[str]]:
    """
    Query NVD for CVEs related to `software` at `version`.

    Returns (cve_records, errors).
    """
    headers = {"apiKey": api_key} if api_key else {}
    # Use keyword search — broader than CPE, catches more results
    params = {
        "keywordSearch": f"{software} {version}",
        "resultsPerPage": min(DEFAULT_RESULTS_PER_PAGE, max_results),
        "startIndex": 0,
    }

    cve_records: list[CVERecord] = []
    errors: list[str] = []
    fetched = 0

    with httpx.Client(timeout=30) as client:
        while True:
            for attempt in range(MAX_RETRIES):
                try:
                    resp = client.get(NVD_BASE, params=params, headers=headers)
                    if resp.status_code == 403:
                        logger.warning("NVD 403 – rate limited, waiting %ss", RETRY_WAIT)
                        time.sleep(RETRY_WAIT)
                        continue
                    resp.raise_for_status()
                    break
                except httpx.HTTPStatusError as e:
                    if attempt == MAX_RETRIES - 1:
                        errors.append(f"NVD HTTP error: {e}")
                        return cve_records, errors
                    time.sleep(RETRY_WAIT)
                except httpx.RequestError as e:
                    errors.append(f"NVD request error: {e}")
                    return cve_records, errors

            data = resp.json()
            items = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)

            for item in items:
                cve_records.append(_nvd_item_to_cve_record(item, version))
                fetched += 1
                if fetched >= max_results:
                    return cve_records, errors

            # Pagination
            if fetched >= total or not items:
                break
            params["startIndex"] = fetched
            time.sleep(0.6)   # polite delay between pages

    logger.info("NVD: fetched %d CVEs for %s %s", len(cve_records), software, version)
    return cve_records, errors
