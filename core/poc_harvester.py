"""
VAEL – Stage 3 Orchestrator
Public Exploit / PoC Harvesting

Coordinates GitHub, Exploit-DB, and Nuclei harvesters, deduplicates by URL,
and optionally feeds results back into Stage 2 enrichments to upgrade
the ExploitMaturity signal.

Usage:
    from core.poc_harvester import run_stage3

    stage3 = run_stage3(
        stage2_result,
        github_token="ghp_xxx",
        top_n_cves=5,
    )
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from schemas.stage2 import Stage2Result, ExploitMaturity
from schemas.stage3 import (
    Stage3Result, CVEPoCBundle, PoCRecord, PoCSource, PoCQuality,
)
from core.github_harvester import search_github
from core.exploitdb_harvester import search_exploitdb
from core.nuclei_harvester import search_nuclei
from core.packet_storm_harvester import search_packet_storm
from core.metasploit_harvester import search_metasploit
from core.intl_harvester import run_intl_harvest
from core.pastebin_harvester import search_pastebin

logger = logging.getLogger(__name__)


def _deduplicate(pocs: list[PoCRecord]) -> list[PoCRecord]:
    """Drop duplicate PoCs by URL. Keep the one with highest quality."""
    quality_rank = {
        PoCQuality.WEAPONIZED: 4,
        PoCQuality.FUNCTIONAL: 3,
        PoCQuality.CONCEPTUAL: 2,
        PoCQuality.UNKNOWN:    1,
        PoCQuality.FAKE:       0,
    }
    by_url: dict[str, PoCRecord] = {}
    for p in pocs:
        existing = by_url.get(p.url)
        if existing is None or quality_rank[p.quality] > quality_rank[existing.quality]:
            by_url[p.url] = p
    return list(by_url.values())


def _sort_pocs(pocs: list[PoCRecord]) -> list[PoCRecord]:
    """Sort PoCs: quality descending, then compatibility, then stars."""
    quality_rank = {
        PoCQuality.WEAPONIZED: 4,
        PoCQuality.FUNCTIONAL: 3,
        PoCQuality.CONCEPTUAL: 2,
        PoCQuality.UNKNOWN:    1,
        PoCQuality.FAKE:       0,
    }
    compat_rank = {
        "CONFIRMED": 3,
        "LIKELY":    2,
        "UNKNOWN":   1,
        "INCOMPATIBLE": 0,
    }

    def key(p: PoCRecord):
        return (
            -quality_rank[p.quality],
            -compat_rank.get(p.version_compatibility.value, 0),
            -(p.stars or 0),
        )

    return sorted(pocs, key=key)


def harvest_cve(
    cve_id: str,
    target_version: str,
    github_token: Optional[str],
    allow_network: bool,
    skip_github:       bool = False,
    skip_edb:          bool = False,
    skip_nuclei:       bool = False,
    skip_packet_storm: bool = False,
    skip_metasploit:   bool = False,
    skip_intl:         bool = False,
    skip_pastebin:     bool = False,
) -> tuple[CVEPoCBundle, list[str]]:
    """Run all harvesters for a single CVE in parallel."""
    bundle = CVEPoCBundle(cve_id=cve_id)
    errors: list[str] = []
    all_pocs: list[PoCRecord] = []

    tasks: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        if allow_network and not skip_github:
            tasks["github"] = pool.submit(
                search_github, cve_id, target_version, github_token=github_token
            )
        if not skip_edb:
            tasks["edb"] = pool.submit(
                search_exploitdb, cve_id, target_version, allow_network=allow_network
            )
        if allow_network and not skip_nuclei:
            tasks["nuclei"] = pool.submit(
                search_nuclei, cve_id, target_version, allow_network=allow_network
            )
        if allow_network and not skip_packet_storm:
            tasks["packet_storm"] = pool.submit(
                search_packet_storm, cve_id, target_version, allow_network=allow_network
            )
        if allow_network and not skip_metasploit:
            tasks["metasploit"] = pool.submit(
                search_metasploit, cve_id, target_version,
                github_token=github_token, allow_network=allow_network,
            )
        if allow_network and not skip_intl:
            tasks["intl"] = pool.submit(
                run_intl_harvest, cve_id, target_version, allow_network=allow_network
            )
        if allow_network and not skip_pastebin:
            tasks["pastebin"] = pool.submit(
                search_pastebin, cve_id, target_version, allow_network=allow_network
            )

        for name, fut in tasks.items():
            try:
                pocs, errs = fut.result()
                all_pocs.extend(pocs)
                errors.extend(errs)
            except Exception as e:
                errors.append(f"{name} harvest failed for {cve_id}: {e}")

    bundle.pocs = _sort_pocs(_deduplicate(all_pocs))
    bundle.compute_aggregate()
    return bundle, errors


def update_stage2_maturity(
    stage2: Stage2Result,
    stage3: Stage3Result,
) -> None:
    """
    Feed Stage 3 findings back into Stage 2 enrichments.

    If we found WEAPONIZED PoCs → upgrade maturity.
    If we found FUNCTIONAL PoCs with confirmed version → upgrade maturity.
    This does NOT re-score VEP tiers (that stays stable after Stage 2).

    Mutates stage2 in place for convenience.
    """
    for bundle in stage3.bundles:
        enrichment = next(
            (e for e in stage2.enrichments if e.cve_id == bundle.cve_id),
            None,
        )
        if not enrichment:
            continue

        has_compatible = bundle.compatible_pocs_count > 0
        current_maturity = enrichment.exploit_maturity

        # Upgrade rules — only move upward
        ranking = {
            ExploitMaturity.UNKNOWN:          0,
            ExploitMaturity.UNPROVEN:         1,
            ExploitMaturity.PROOF_OF_CONCEPT: 2,
            ExploitMaturity.FUNCTIONAL:       3,
            ExploitMaturity.WEAPONIZED:       4,
        }

        new_maturity = current_maturity
        if bundle.best_quality == PoCQuality.WEAPONIZED:
            new_maturity = ExploitMaturity.WEAPONIZED
        elif bundle.best_quality == PoCQuality.FUNCTIONAL and has_compatible:
            new_maturity = ExploitMaturity.FUNCTIONAL
        elif bundle.best_quality == PoCQuality.FUNCTIONAL:
            new_maturity = max(
                (current_maturity, ExploitMaturity.PROOF_OF_CONCEPT),
                key=lambda m: ranking[m],
            )
        elif bundle.best_quality == PoCQuality.CONCEPTUAL:
            new_maturity = max(
                (current_maturity, ExploitMaturity.PROOF_OF_CONCEPT),
                key=lambda m: ranking[m],
            )

        if ranking[new_maturity] > ranking[current_maturity]:
            enrichment.exploit_maturity = new_maturity
            enrichment.reasoning.append(
                f"Stage 3: maturity upgraded {current_maturity.value} → "
                f"{new_maturity.value} ({bundle.total_found} PoCs, "
                f"{bundle.compatible_pocs_count} compatible)"
            )


def run_stage3(
    stage2: Stage2Result,
    github_token: Optional[str] = None,
    top_n_cves: int = 10,
    allow_network: bool = True,
    update_stage2: bool = True,
    skip_github:       bool = False,
    skip_edb:          bool = False,
    skip_nuclei:       bool = False,
    skip_packet_storm: bool = False,
    skip_metasploit:   bool = False,
    skip_intl:         bool = False,
    skip_pastebin:     bool = False,
) -> Stage3Result:
    """
    Harvest public exploits for the top-N priority CVEs from Stage 2.

    Args:
        stage2:         Stage 2 result (CVEs already scored)
        github_token:   GitHub PAT for higher rate limits
        top_n_cves:     Only harvest for the top-N priority CVEs (rate-limit safety)
        allow_network:  Master offline switch
        update_stage2:  Feed findings back into Stage 2 exploit_maturity

    Returns:
        Stage3Result with per-CVE PoC bundles.
    """
    logger.info(
        "Stage 3 starting for %s %s (top %d CVEs)",
        stage2.software, stage2.version, top_n_cves,
    )

    result = Stage3Result(
        software=stage2.software,
        version=stage2.version,
    )

    # Pick top priority CVEs from Stage 2 (sorted by VEP score)
    top = stage2.top_priority_cves(limit=top_n_cves)
    if not top:
        logger.info("No CVEs to harvest for")
        return result

    # Track every source that was attempted, regardless of whether it returned results.
    # This lets the UI show "PASTEBIN searched — 0 results" rather than silently omitting it.
    attempted_sources: set[str] = set()
    if allow_network and not skip_github:       attempted_sources.add("GITHUB")
    if not skip_edb:                            attempted_sources.add("EXPLOIT_DB")
    if allow_network and not skip_nuclei:       attempted_sources.add("NUCLEI")
    if allow_network and not skip_packet_storm: attempted_sources.add("PACKET_STORM")
    if allow_network and not skip_metasploit:   attempted_sources.add("METASPLOIT")
    if allow_network and not skip_intl:         attempted_sources.update({"GITEE", "SEEBUG"})
    if allow_network and not skip_pastebin:     attempted_sources.add("PASTEBIN")
    sources_with_results: set[str] = set()

    # Process up to 2 CVEs concurrently — respects GitHub rate limits while
    # still giving a meaningful speedup when top_n > 1.
    max_workers = min(2, len(top))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        cve_futures = {
            pool.submit(
                harvest_cve,
                cve_id=cve.cve_id,
                target_version=stage2.version,
                github_token=github_token,
                allow_network=allow_network,
                skip_github=skip_github,
                skip_edb=skip_edb,
                skip_nuclei=skip_nuclei,
                skip_packet_storm=skip_packet_storm,
                skip_metasploit=skip_metasploit,
                skip_intl=skip_intl,
                skip_pastebin=skip_pastebin,
            ): cve
            for cve, _enrichment in top
        }
        for fut in as_completed(cve_futures):
            try:
                bundle, errs = fut.result()
                result.bundles.append(bundle)
                result.errors.extend(errs)
                for p in bundle.pocs:
                    sources_with_results.add(p.source.value)
            except Exception as e:
                result.errors.append(f"CVE harvest failed: {e}")

    # Re-order bundles to match the VEP priority order from Stage 2 so the
    # AI prompt and web UI always present CVEs highest-priority first.
    priority_order = {cve.cve_id: i for i, (cve, _) in enumerate(top)}
    result.bundles.sort(key=lambda b: priority_order.get(b.cve_id, 999))

    # sources_queried = all attempted; sources_with_results is a subset when needed
    result.sources_queried = sorted(attempted_sources)
    result.compute_summary()

    # Surface rate limit warnings and strip them from errors
    from core.rate_limiter import rate_limiter
    from core.config import settings as _cfg
    rl_warnings = rate_limiter.collect_warnings(
        ["github", "github_search", "packet_storm", "gitee", "seebug", "yandex", "baidu", "naver", "pastebin"],
        {
            "github":        bool(_cfg.github_token),
            "github_search": bool(_cfg.github_token),
            "packet_storm":  False,
            "gitee":         False,
            "seebug":        False,
            "yandex":        False,
            "baidu":         False,
            "naver":         False,
            "pastebin":      False,
        },
    )
    rl_warnings += [e for e in result.errors if e.startswith("[RateLimit]")]
    result.errors = [e for e in result.errors if not e.startswith("[RateLimit]")]
    result.rate_limit_warnings = list(dict.fromkeys(rl_warnings))

    if update_stage2:
        update_stage2_maturity(stage2, result)

    logger.info(
        "Stage 3 complete: %d PoCs across %d CVEs (%d weaponized)",
        result.total_pocs, len(result.bundles), result.weaponized_count,
    )
    return result
