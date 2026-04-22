"""
VAEL – Stage 1 Orchestrator
Known Vulnerability Mapping

Coordinates NVD + OSV fetchers and misconfig mapper,
deduplicates results, and returns a Stage1Result.

Usage:
    from core.cve_mapper import run_stage1
    result = run_stage1("log4j", "2.14.1")
"""

from __future__ import annotations

import logging
from typing import Optional

from schemas.stage1 import Stage1Result, CVERecord
from core.nvd_fetcher import fetch_nvd
from core.osv_fetcher import fetch_osv
from core.misconfig_mapper import get_misconfig_flags
from core.version_utils import best_cpe

logger = logging.getLogger(__name__)


def _deduplicate(records: list[CVERecord]) -> list[CVERecord]:
    """
    Merge duplicate CVE IDs across sources.
    NVD record is preferred (more complete CVSS data).
    OSV record is kept if NVD didn't find it.
    """
    seen: dict[str, CVERecord] = {}
    for r in records:
        cve_id = r.cve_id.upper()
        if cve_id not in seen:
            seen[cve_id] = r
        else:
            existing = seen[cve_id]
            # Prefer NVD for CVSS; prefer whichever has version_matched=True
            if r.source == "NVD" and existing.source != "NVD":
                seen[cve_id] = r
            if r.version_matched and not existing.version_matched:
                seen[cve_id].version_matched = True
            # Merge CWEs
            existing_cwe_ids = {c.cwe_id for c in seen[cve_id].cwes}
            for cwe in r.cwes:
                if cwe.cwe_id not in existing_cwe_ids:
                    seen[cve_id].cwes.append(cwe)
    return list(seen.values())


def _sort_cves(records: list[CVERecord]) -> list[CVERecord]:
    """Sort CVEs: version-matched first, then by CVSS score descending."""
    def sort_key(r: CVERecord):
        score = r.cvss_v3.score if r.cvss_v3 and r.cvss_v3.score else 0.0
        return (0 if r.version_matched else 1, -score)
    return sorted(records, key=sort_key)


def run_stage1(
    software: str,
    version: str,
    cpe_string: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    osv_ecosystem: Optional[str] = None,
    max_results_per_source: int = 100,
    skip_osv: bool = False,
    skip_nvd: bool = False,
) -> Stage1Result:
    """
    Main entry point for Stage 1.

    Args:
        software:              Software name (e.g. "log4j", "nginx")
        version:               Version string (e.g. "2.14.1", "1.20.0")
        cpe_string:            Optional CPE 2.3 string (auto-generated if None)
        nvd_api_key:           Optional NVD API key for higher rate limits
        osv_ecosystem:         Optional OSV ecosystem hint (e.g. "Maven", "PyPI")
        max_results_per_source: Max CVEs to fetch from each source
        skip_osv / skip_nvd:   For offline/testing use

    Returns:
        Stage1Result with all CVEs, misconfigs, and summary stats.
    """
    logger.info("Stage 1 starting: %s %s", software, version)

    result = Stage1Result(
        software=software,
        version=version,
        cpe_string=cpe_string or best_cpe(software, version),
    )

    all_cves: list[CVERecord] = []
    sources_queried: list[str] = []

    # ── NVD ──────────────────────────────────────────────────────────────────
    if not skip_nvd:
        logger.info("Querying NVD...")
        nvd_cves, nvd_errors = fetch_nvd(
            software=software,
            version=version,
            api_key=nvd_api_key,
            max_results=max_results_per_source,
        )
        all_cves.extend(nvd_cves)
        result.errors.extend(nvd_errors)
        sources_queried.append("NVD")
        logger.info("NVD returned %d CVEs", len(nvd_cves))

    # ── OSV ──────────────────────────────────────────────────────────────────
    if not skip_osv:
        logger.info("Querying OSV...")
        osv_cves, osv_errors = fetch_osv(
            software=software,
            version=version,
            ecosystem=osv_ecosystem,
            max_results=max_results_per_source,
        )
        all_cves.extend(osv_cves)
        result.errors.extend(osv_errors)
        sources_queried.append("OSV")
        logger.info("OSV returned %d CVEs", len(osv_cves))

    # ── Deduplicate + Sort ────────────────────────────────────────────────────
    result.cves = _sort_cves(_deduplicate(all_cves))

    # ── Misconfig Flags ───────────────────────────────────────────────────────
    result.misconfig_flags = get_misconfig_flags(software)
    sources_queried.append("CWE/CIS-local")

    # ── Finalise ──────────────────────────────────────────────────────────────
    result.sources_queried = sources_queried
    result.compute_summary()

    logger.info(
        "Stage 1 complete: %d CVEs (%d version-matched), %d misconfig flags",
        result.total_cves, result.version_matched_count, len(result.misconfig_flags),
    )
    return result
