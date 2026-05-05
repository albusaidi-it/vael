"""
VAEL – Delta Tracker / Monitoring Mode

Persists a baseline snapshot of a Stage2+Stage3 analysis and diffs
subsequent runs against it, surfacing only what changed.

Snapshots are stored in the SQLite cache (source="snapshot") so they
share the same cache lifecycle as all other VAEL data.

Usage:
    from core.delta_tracker import save_snapshot, diff_snapshots

    # First run — save baseline
    save_snapshot(stage2, stage3)

    # Later run — get a diff
    report = diff_snapshots(software, version, new_stage2, new_stage3)
    if report.has_critical_changes:
        notify(report)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Optional

from schemas.stage2 import Stage2Result, VEPTier, ExploitMaturity
from schemas.stage3 import Stage3Result
from schemas.delta import DeltaReport, CVEDelta, ChangeType
from core import cache as _cache

logger = logging.getLogger(__name__)

_SNAPSHOT_TTL = 90 * 24 * 3600   # keep snapshots for 90 days
_EPSS_SPIKE_THRESHOLD = 0.10      # ≥10pp increase counts as a spike


def _snapshot_key(software: str, version: str) -> str:
    return _cache.make_key("snapshot", software, version)


def save_snapshot(stage2: Stage2Result, stage3: Optional[Stage3Result] = None) -> None:
    """Persist the current analysis as the new baseline."""
    key  = _snapshot_key(stage2.software, stage2.version)
    data = {
        "software":    stage2.software,
        "version":     stage2.version,
        "saved_at":    datetime.utcnow().isoformat(),
        "stage2":      stage2.model_dump(mode="json"),
        "stage3":      stage3.model_dump(mode="json") if stage3 else None,
    }
    _cache.set(key, "snapshot", data, _SNAPSHOT_TTL)
    logger.info("Snapshot saved for %s %s", stage2.software, stage2.version)


def load_snapshot(software: str, version: str) -> Optional[dict]:
    """Load saved baseline snapshot. Returns raw dict or None."""
    key = _snapshot_key(software, version)
    return _cache.get(key)


def diff_snapshots(
    software: str,
    version: str,
    new_stage2: Stage2Result,
    new_stage3: Optional[Stage3Result] = None,
) -> DeltaReport:
    """
    Compare a new analysis against the saved baseline.
    Returns a DeltaReport. If no baseline exists, all CVEs appear as NEW_CVE.
    """
    report = DeltaReport(
        software=software,
        version=version,
        current_ts=datetime.utcnow(),
    )

    snapshot = load_snapshot(software, version)
    if snapshot is None:
        logger.info("No baseline snapshot for %s %s — treating all CVEs as new", software, version)
        for enrichment in new_stage2.enrichments:
            report.changes.append(CVEDelta(
                cve_id=enrichment.cve_id,
                change_type=ChangeType.NEW_CVE,
                new_value=enrichment.vep_tier.value,
                detail="No baseline — first-time analysis",
            ))
        report.compute_summary()
        return report

    # Parse baseline
    try:
        baseline_s2 = Stage2Result.model_validate(snapshot["stage2"])
        baseline_s3 = (
            Stage3Result.model_validate(snapshot["stage3"])
            if snapshot.get("stage3") else None
        )
        report.baseline_ts = datetime.fromisoformat(snapshot.get("saved_at", ""))
    except Exception as e:
        logger.warning("Failed to parse snapshot: %s", e)
        report.changes.append(CVEDelta(
            cve_id="N/A",
            change_type=ChangeType.NEW_CVE,
            detail=f"Baseline snapshot corrupt: {e}",
        ))
        report.compute_summary()
        return report

    # Build lookup maps
    old_enrich = {e.cve_id: e for e in baseline_s2.enrichments}
    new_enrich = {e.cve_id: e for e in new_stage2.enrichments}

    _tier_rank = {
        VEPTier.T_UNKNOWN:    0,
        VEPTier.T3_DEFER:     1,
        VEPTier.T2_MONITOR:   2,
        VEPTier.T1_HIGH:      3,
        VEPTier.T0_PATCH_NOW: 4,
    }
    _mat_rank = {
        ExploitMaturity.UNKNOWN:          0,
        ExploitMaturity.UNPROVEN:         1,
        ExploitMaturity.PROOF_OF_CONCEPT: 2,
        ExploitMaturity.FUNCTIONAL:       3,
        ExploitMaturity.WEAPONIZED:       4,
    }

    # ── CVE-level changes ──────────────────────────────────────────────────────
    for cve_id, new_e in new_enrich.items():
        old_e = old_enrich.get(cve_id)

        if old_e is None:
            # Completely new CVE
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.NEW_CVE,
                new_value=new_e.vep_tier.value,
                detail=f"CVE not present in baseline, tier={new_e.vep_tier.value}",
            ))
            continue

        # Tier change
        old_rank = _tier_rank.get(old_e.vep_tier, 0)
        new_rank = _tier_rank.get(new_e.vep_tier, 0)
        if new_rank > old_rank:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.TIER_UPGRADE,
                old_value=old_e.vep_tier.value,
                new_value=new_e.vep_tier.value,
                detail=f"Priority tier escalated: {old_e.vep_tier.value} → {new_e.vep_tier.value}",
            ))
        elif new_rank < old_rank:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.TIER_DOWNGRADE,
                old_value=old_e.vep_tier.value,
                new_value=new_e.vep_tier.value,
                detail=f"Tier de-escalated: {old_e.vep_tier.value} → {new_e.vep_tier.value}",
            ))

        # KEV change
        if new_e.in_kev and not old_e.in_kev:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.KEV_ADDED,
                detail="Added to CISA Known Exploited Vulnerabilities catalog",
            ))
        elif not new_e.in_kev and old_e.in_kev:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.KEV_REMOVED,
                detail="Removed from CISA KEV catalog",
            ))

        # EPSS spike
        old_epss = old_e.epss.epss if old_e.epss else 0.0
        new_epss = new_e.epss.epss if new_e.epss else 0.0
        delta    = new_epss - old_epss
        if delta >= _EPSS_SPIKE_THRESHOLD:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.EPSS_SPIKE,
                old_value=f"{old_epss:.3f}",
                new_value=f"{new_epss:.3f}",
                detail=f"EPSS exploitation probability increased by {delta:+.1%}",
            ))
        elif delta <= -_EPSS_SPIKE_THRESHOLD:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.EPSS_DROP,
                old_value=f"{old_epss:.3f}",
                new_value=f"{new_epss:.3f}",
                detail=f"EPSS score decreased by {delta:+.1%}",
            ))

        # Maturity upgrade
        old_mat_rank = _mat_rank.get(old_e.exploit_maturity, 0)
        new_mat_rank = _mat_rank.get(new_e.exploit_maturity, 0)
        if new_mat_rank > old_mat_rank:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.MATURITY_CHANGE,
                old_value=old_e.exploit_maturity.value,
                new_value=new_e.exploit_maturity.value,
                detail=f"Exploit maturity upgraded: {old_e.exploit_maturity.value} → {new_e.exploit_maturity.value}",
            ))

    # Removed CVEs
    for cve_id in old_enrich:
        if cve_id not in new_enrich:
            report.changes.append(CVEDelta(
                cve_id=cve_id,
                change_type=ChangeType.REMOVED_CVE,
                old_value=old_enrich[cve_id].vep_tier.value,
                detail="CVE no longer returned by vulnerability sources",
            ))

    # ── PoC changes (Stage 3) ──────────────────────────────────────────────────
    if new_stage3 and baseline_s3:
        old_poc_urls: set[str] = {
            p.url for b in baseline_s3.bundles for p in b.pocs
        }
        for bundle in new_stage3.bundles:
            for poc in bundle.pocs:
                if poc.url not in old_poc_urls:
                    from schemas.stage3 import PoCQuality
                    change_type = (
                        ChangeType.NEW_WEAPON
                        if poc.quality == PoCQuality.WEAPONIZED
                        else ChangeType.NEW_POC
                    )
                    report.changes.append(CVEDelta(
                        cve_id=bundle.cve_id,
                        change_type=change_type,
                        new_value=poc.quality.value,
                        detail=f"New {'weaponized ' if change_type == ChangeType.NEW_WEAPON else ''}PoC: {poc.url}",
                    ))
    elif new_stage3 and not baseline_s3:
        for bundle in new_stage3.bundles:
            for poc in bundle.pocs:
                from schemas.stage3 import PoCQuality
                report.changes.append(CVEDelta(
                    cve_id=bundle.cve_id,
                    change_type=ChangeType.NEW_POC,
                    new_value=poc.quality.value,
                    detail=f"PoC discovered (no prior baseline): {poc.url}",
                ))

    report.compute_summary()
    logger.info(
        "Delta for %s %s: %d changes (%d high-signal)",
        software, version, len(report.changes), len(report.high_signal_changes),
    )
    return report
