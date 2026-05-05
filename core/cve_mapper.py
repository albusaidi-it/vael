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
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional

from schemas.stage1 import Stage1Result, CVERecord
from core.nvd_fetcher import fetch_nvd
from core.osv_fetcher import fetch_osv
from core.ghsa_fetcher import fetch_ghsa
from core.attackerkb_fetcher import fetch_attackerkb
from core.misconfig_mapper import get_misconfig_flags
from core.version_utils import best_cpe
from core.name_resolver import resolve, resolve_ecosystem

logger = logging.getLogger(__name__)


def _deduplicate(records: list[CVERecord]) -> list[CVERecord]:
    """
    Merge duplicate CVE IDs across sources.
    NVD is preferred for CVSS data. version_matched=True propagates from
    any source to the winner — previously this flag was lost when NVD
    replaced an OSV/GHSA record that had version_matched=True.
    CWEs and references are always merged from all sources.
    """
    seen: dict[str, CVERecord] = {}
    for r in records:
        cve_id = r.cve_id.upper()
        if cve_id not in seen:
            seen[cve_id] = r
            continue

        existing = seen[cve_id]
        # Prefer NVD for CVSS completeness
        if r.source == "NVD" and existing.source != "NVD":
            # Carry over signals from the record being replaced
            had_version_match = existing.version_matched or r.version_matched
            # NVD CVSS wins, but if NVD has none (rare), fall back to OSV/GHSA
            if r.cvss_v3 is None and existing.cvss_v3 is not None:
                r.cvss_v3 = existing.cvss_v3
            if r.cvss_v2 is None and existing.cvss_v2 is not None:
                r.cvss_v2 = existing.cvss_v2
            # OSV/GHSA are often published days before NVD — keep the earlier date
            if existing.published and (
                r.published is None or existing.published < r.published
            ):
                r.published = existing.published
            # Merge existing's CWEs and refs INTO r before swapping
            existing_cwe_ids = {c.cwe_id for c in r.cwes}
            for cwe in existing.cwes:
                if cwe.cwe_id not in existing_cwe_ids:
                    r.cwes.append(cwe)
            existing_ref_urls = {ref.url for ref in r.references}
            for ref in existing.references:
                if ref.url not in existing_ref_urls:
                    r.references.append(ref)
            seen[cve_id] = r
            seen[cve_id].version_matched = had_version_match
        else:
            # Propagate version_matched=True from any source
            if r.version_matched and not existing.version_matched:
                seen[cve_id].version_matched = True
            # Merge CWEs and refs from r into existing
            existing_cwe_ids = {c.cwe_id for c in seen[cve_id].cwes}
            for cwe in r.cwes:
                if cwe.cwe_id not in existing_cwe_ids:
                    seen[cve_id].cwes.append(cwe)
            existing_ref_urls = {ref.url for ref in seen[cve_id].references}
            for ref in r.references:
                if ref.url not in existing_ref_urls:
                    seen[cve_id].references.append(ref)

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
    max_results_per_source: int = 200,
    skip_osv: bool = False,
    skip_nvd: bool = False,
    skip_ghsa: bool = False,
    skip_attackerkb: bool = False,
    attackerkb_api_key: Optional[str] = None,
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

    # ── Name resolution ──────────────────────────────────────────────────────
    resolved = resolve(software, version)
    clean_version = resolved.clean_version or version
    canonical_software = resolved.canonical_name
    resolved_cpe = cpe_string or resolved.cpe_string() or best_cpe(software, version)
    resolved_ecosystems = resolve_ecosystem(software, osv_ecosystem)

    if resolved.match_method != "fallback":
        logger.info(
            "Name resolved: '%s' → '%s' (%s, %.0f%% confidence)",
            software, canonical_software, resolved.match_method, resolved.confidence * 100,
        )

    result = Stage1Result(
        software=software,
        version=clean_version,
        cpe_string=resolved_cpe,
    )

    all_cves: list[CVERecord] = []
    sources_queried: list[str] = []

    # ── NVD + OSV + misconfig run in parallel ────────────────────────────────
    # NVD: search both raw input and canonical name to maximise recall
    nvd_search_term = canonical_software if resolved.match_method != "fallback" else software

    osv_eco = resolved_ecosystems[0] if resolved_ecosystems else None
    ghsa_eco = osv_eco  # GHSA ecosystem names match OSV

    with ThreadPoolExecutor(max_workers=5) as pool:
        nvd_fut: Optional[Future] = (
            pool.submit(fetch_nvd, software=nvd_search_term, version=clean_version,
                        api_key=nvd_api_key, max_results=max_results_per_source)
            if not skip_nvd else None
        )
        osv_fut: Optional[Future] = (
            pool.submit(fetch_osv,
                        software=resolved.osv_package_name(),
                        version=clean_version,
                        ecosystem=osv_eco,
                        max_results=max_results_per_source)
            if not skip_osv else None
        )
        ghsa_fut: Optional[Future] = (
            pool.submit(fetch_ghsa,
                        software=resolved.osv_package_name(),
                        version=clean_version,
                        ecosystem=ghsa_eco,
                        max_results=max_results_per_source)
            if not skip_ghsa else None
        )
        akb_fut: Optional[Future] = (
            pool.submit(fetch_attackerkb,
                        software=nvd_search_term,
                        version=clean_version,
                        api_key=attackerkb_api_key,
                        max_results=50)
            if not skip_attackerkb else None
        )
        misc_fut: Future = pool.submit(get_misconfig_flags, software)

        if nvd_fut is not None:
            try:
                nvd_cves, nvd_errors = nvd_fut.result()
                all_cves.extend(nvd_cves)
                result.errors.extend(nvd_errors)
                sources_queried.append("NVD")
                logger.info("NVD returned %d CVEs", len(nvd_cves))
            except Exception as e:
                result.errors.append(f"NVD fetch failed: {e}")
                logger.error("NVD fetch failed: %s", e)

        if osv_fut is not None:
            try:
                osv_cves, osv_errors = osv_fut.result()
                all_cves.extend(osv_cves)
                result.errors.extend(osv_errors)
                sources_queried.append("OSV")
                logger.info("OSV returned %d CVEs", len(osv_cves))
            except Exception as e:
                result.errors.append(f"OSV fetch failed: {e}")
                logger.error("OSV fetch failed: %s", e)

        if ghsa_fut is not None:
            try:
                ghsa_cves, ghsa_errors = ghsa_fut.result()
                all_cves.extend(ghsa_cves)
                result.errors.extend(ghsa_errors)
                if ghsa_cves:
                    sources_queried.append("GHSA")
                logger.info("GHSA returned %d CVEs", len(ghsa_cves))
            except Exception as e:
                result.errors.append(f"GHSA fetch failed: {e}")
                logger.error("GHSA fetch failed: %s", e)

        if akb_fut is not None:
            try:
                akb_cves, akb_errors = akb_fut.result()
                all_cves.extend(akb_cves)
                result.errors.extend(akb_errors)
                sources_queried.append("ATTACKERKB")   # always show it was attempted
                logger.info("AttackerKB returned %d CVEs", len(akb_cves))
            except Exception as e:
                result.errors.append(f"AttackerKB fetch failed: {e}")
                logger.error("AttackerKB fetch failed: %s", e)

        try:
            result.misconfig_flags = misc_fut.result()
        except Exception as e:
            logger.error("Misconfig mapper failed: %s", e)

    # ── Deduplicate + Sort ────────────────────────────────────────────────────
    result.cves = _sort_cves(_deduplicate(all_cves))
    sources_queried.append("CWE/CIS-local")

    # ── Rate limit warnings ───────────────────────────────────────────────────
    from core.rate_limiter import rate_limiter
    from core.config import settings as _cfg
    rl_warnings = rate_limiter.collect_warnings(
        ["nvd", "ghsa", "attackerkb"],
        {
            "nvd":         bool(_cfg.nvd_api_key),
            "ghsa":        bool(_cfg.github_token),
            "attackerkb":  bool(attackerkb_api_key or _cfg.attackerkb_api_key),
        },
    )
    # Also surface any [RateLimit] prefixed messages that crept into errors
    rl_warnings += [e for e in result.errors if e.startswith("[RateLimit]")]
    result.errors = [e for e in result.errors if not e.startswith("[RateLimit]")]
    result.rate_limit_warnings = list(dict.fromkeys(rl_warnings))  # dedup, preserve order

    # ── Finalise ──────────────────────────────────────────────────────────────
    result.sources_queried = sources_queried
    result.compute_summary()

    logger.info(
        "Stage 1 complete: %d CVEs (%d version-matched), %d misconfig flags",
        result.total_cves, result.version_matched_count, len(result.misconfig_flags),
    )
    return result
