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
    skip_github: bool = False,
    skip_edb: bool = False,
    skip_nuclei: bool = False,
) -> tuple[CVEPoCBundle, list[str]]:
    """Run all harvesters for a single CVE."""
    bundle = CVEPoCBundle(cve_id=cve_id)
    errors: list[str] = []
    all_pocs: list[PoCRecord] = []

    # Run harvesters sequentially for rate-limit safety.
    # (Could parallelize by source; GitHub is the rate-limit bottleneck.)

    if allow_network and not skip_github:
        try:
            pocs, errs = search_github(cve_id, target_version, github_token=github_token)
            all_pocs.extend(pocs)
            errors.extend(errs)
        except Exception as e:
            errors.append(f"GitHub harvest failed for {cve_id}: {e}")

    if not skip_edb:
        try:
            pocs, errs = search_exploitdb(cve_id, target_version, allow_network=allow_network)
            all_pocs.extend(pocs)
            errors.extend(errs)
        except Exception as e:
            errors.append(f"EDB harvest failed for {cve_id}: {e}")

    if allow_network and not skip_nuclei:
        try:
            pocs, errs = search_nuclei(cve_id, target_version, allow_network=allow_network)
            all_pocs.extend(pocs)
            errors.extend(errs)
        except Exception as e:
            errors.append(f"Nuclei harvest failed for {cve_id}: {e}")

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
    top_n_cves: int = 5,
    allow_network: bool = True,
    update_stage2: bool = True,
    skip_github: bool = False,
    skip_edb: bool = False,
    skip_nuclei: bool = False,
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

    sources: set[str] = set()

    for cve, enrichment in top:
        bundle, errors = harvest_cve(
            cve_id=cve.cve_id,
            target_version=stage2.version,
            github_token=github_token,
            allow_network=allow_network,
            skip_github=skip_github,
            skip_edb=skip_edb,
            skip_nuclei=skip_nuclei,
        )
        result.bundles.append(bundle)
        result.errors.extend(errors)
        for p in bundle.pocs:
            sources.add(p.source.value)

    result.sources_queried = sorted(sources)
    result.compute_summary()

    if update_stage2:
        update_stage2_maturity(stage2, result)

    logger.info(
        "Stage 3 complete: %d PoCs across %d CVEs (%d weaponized)",
        result.total_pocs, len(result.bundles), result.weaponized_count,
    )
    return result
