"""
VAEL – Stage 1 / NVD Fetcher
Queries the NVD API v2 for CVEs matching software + version.

Docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 req/30s without API key, 50 req/30s with key.
"""

from __future__ import annotations

import logging
import random as _random
import time
from typing import Optional
import httpx
from core import http_client

from schemas.stage1 import (
    CVERecord, CVSSv3, CVSSv2, CWEEntry, Reference, CPEMatch, Severity
)
from core.version_utils import version_in_range
from core import cache as _cache
from core.rate_limiter import rate_limiter
from core.utils import severity_from_score

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 100
RETRY_WAIT = 6
MAX_RETRIES = 3
_TTL = int(24 * 3600 * (0.9 + _random.random() * 0.2))  # 21.6–26.4 h jitter


def _cache_load(software: str, version: str, max_results: int):
    # Cache key intentionally excludes max_results so any call for the same
    # (software, version) pair reuses the same cached fetch.
    key  = _cache.make_key("nvd", software, version)
    data = _cache.get(key)
    if data is None:
        return None
    try:
        all_cves = [CVERecord.model_validate(r) for r in data["cves"]]
        return all_cves[:max_results], data.get("errors", [])
    except Exception:
        return None


def _cache_save(software: str, version: str, max_results: int,
                cves: list[CVERecord], errors: list[str]) -> None:
    key = _cache.make_key("nvd", software, version)
    _cache.set(key, "nvd", {"cves": [r.model_dump(mode="json") for r in cves], "errors": errors}, _TTL)


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
                severity=severity_from_score(score),
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
            severity=severity_from_score(score),
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
    """Query NVD for CVEs related to `software` at `version`. Returns (cve_records, errors)."""
    cached = _cache_load(software, version, max_results)
    if cached is not None:
        logger.info("NVD cache hit for %s %s (%d CVEs)", software, version, len(cached[0]))
        return cached

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

    has_key = bool(api_key)
    client = http_client.api
    while True:
        # Pre-flight rate limit check
        warn = rate_limiter.warn_and_log("nvd", has_key)
        if warn:
            errors.append(f"[RateLimit] {warn}")

        for attempt in range(MAX_RETRIES):
            try:
                resp = client.get(NVD_BASE, params=params, headers=headers, timeout=30)
                rate_limiter.record("nvd", dict(resp.headers), resp.status_code)
                if resp.status_code == 403:
                    retry_after = int(resp.headers.get("retry-after", RETRY_WAIT))
                    wait = max(retry_after, RETRY_WAIT)
                    logger.warning("NVD 403 – rate limited, waiting %ss", wait)
                    errors.append(
                        f"[RateLimit] NVD rate limit hit. "
                        f"{'Add NVD_API_KEY for 10x higher limits.' if not has_key else f'Retrying after {wait}s.'}"
                    )
                    time.sleep(wait)
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
    _cache_save(software, version, max_results, cve_records, errors)
    return cve_records, errors
