"""
VAEL API – Demo / fixture routes.
  GET /demo/scenarios
  GET /demo/{scenario_id}
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from api.routes.analyze import FullAnalysisResponse

router = APIRouter(prefix="/demo", tags=["Demo"])


@router.get("/scenarios")
def demo_scenarios():
    """List available offline demo scenarios (loaded from fixtures/)."""
    from core.fixtures import list_fixtures
    return {"scenarios": list_fixtures()}


@router.get("/{scenario_id}", response_model=FullAnalysisResponse)
def demo_scenario(scenario_id: str):
    """Return pre-built fixture data for a demo scenario — no network calls."""
    from core.fixtures import load_fixture_by_id
    fixture = load_fixture_by_id(scenario_id)
    if fixture is None:
        raise HTTPException(404, detail=f"Demo scenario '{scenario_id}' not found. "
                            f"Available: log4shell, spring4shell")
    s1, s2, s3, verdict = fixture
    return FullAnalysisResponse(stage1=s1, stage2=s2, stage3=s3, verdict=verdict)
