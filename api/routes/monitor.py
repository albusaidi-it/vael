"""
VAEL API – Monitoring / delta routes.
  POST /analyze/delta
  GET  /monitor/{software}/{version}
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from core.cve_mapper import run_stage1
from core.exploit_eval import run_stage2
from core.poc_harvester import run_stage3
from schemas.delta import DeltaReport

from api.routes.analyze import FullAnalysisRequest, _validate

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Monitoring"])


@router.post("/analyze/delta", response_model=DeltaReport)
def analyze_delta(req: FullAnalysisRequest):
    """
    Run a full pipeline scan and diff against the saved baseline.
    If no baseline exists, saves this run as the new baseline and returns
    all CVEs as NEW_CVE changes.
    """
    _validate(req)
    from core.delta_tracker import save_snapshot, diff_snapshots
    try:
        s1 = run_stage1(software=req.software.strip(), version=req.version.strip())
        s2 = run_stage2(s1, allow_network=not req.offline)
        s3 = run_stage3(s2, top_n_cves=req.top_n, allow_network=not req.offline,
                        skip_github=req.skip_github)
        report = diff_snapshots(req.software.strip(), req.version.strip(), s2, s3)
        save_snapshot(s2, s3)
        return report
    except Exception as e:
        logger.exception("Delta analysis error")
        raise HTTPException(500, detail=str(e))


@router.get("/monitor/{software}/{version}", response_model=dict)
def monitor_status(software: str, version: str):
    """Check if a baseline snapshot exists and when it was saved."""
    from core.delta_tracker import load_snapshot
    snap = load_snapshot(software, version)
    if snap is None:
        return {"has_baseline": False, "software": software, "version": version}
    return {
        "has_baseline": True,
        "software": software,
        "version": version,
        "saved_at": snap.get("saved_at"),
        "cve_count": len(snap.get("stage2", {}).get("enrichments", [])),
    }
