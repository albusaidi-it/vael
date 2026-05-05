"""
VAEL – Offline Fixture System
Loads pre-built analysis results from JSON files in fixtures/ for offline demos and testing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, NamedTuple

from schemas.stage1 import Stage1Result
from schemas.stage2 import Stage2Result
from schemas.stage3 import Stage3Result
from core.ai_reasoner import RiskVerdict

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

# Map of (software_lower, version) → fixture filename
_FIXTURE_INDEX: dict[str, str] = {
    "log4j:2.14.1":           "log4shell.json",
    "log4j-core:2.14.1":      "log4shell.json",
    "spring-framework:5.3.17": "spring4shell.json",
    "spring:5.3.17":           "spring4shell.json",
}

# Human-readable labels for the demo picker
DEMO_SCENARIOS: list[dict] = [
    {
        "id": "log4shell",
        "software": "log4j",
        "version": "2.14.1",
        "label": "Log4Shell (CVE-2021-44228) — CVSS 10.0, KEV, EPSS 97.6%",
        "file": "log4shell.json",
    },
    {
        "id": "spring4shell",
        "software": "spring-framework",
        "version": "5.3.17",
        "label": "Spring4Shell (CVE-2022-22965) — CVSS 9.8, KEV, EPSS 97.4%",
        "file": "spring4shell.json",
    },
]


class FixtureResult(NamedTuple):
    stage1: Stage1Result
    stage2: Stage2Result
    stage3: Stage3Result
    verdict: RiskVerdict


def _load_json(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _populate_stage2_cves(data: dict) -> dict:
    """Stage2 stage1_cves field is stored empty in fixtures to avoid duplication; fill it."""
    if not data["stage2"].get("stage1_cves"):
        data["stage2"]["stage1_cves"] = data["stage1"]["cves"]
    return data


def load_fixture(software: str, version: str) -> Optional[FixtureResult]:
    """Return a FixtureResult for the given software/version, or None if not found."""
    key = f"{software.lower()}:{version}"
    filename = _FIXTURE_INDEX.get(key)
    if filename is None:
        return None
    path = FIXTURES_DIR / filename
    if not path.exists():
        return None
    raw = _populate_stage2_cves(_load_json(path))
    return FixtureResult(
        stage1=Stage1Result.model_validate(raw["stage1"]),
        stage2=Stage2Result.model_validate(raw["stage2"]),
        stage3=Stage3Result.model_validate(raw["stage3"]),
        verdict=RiskVerdict.model_validate(raw["verdict"]),
    )


def load_fixture_by_id(scenario_id: str) -> Optional[FixtureResult]:
    """Load a fixture by its scenario ID (e.g. 'log4shell')."""
    for s in DEMO_SCENARIOS:
        if s["id"] == scenario_id:
            return load_fixture(s["software"], s["version"])
    return None


def load_fixture_file(filename: str) -> Optional[FixtureResult]:
    """Load a fixture directly by filename (e.g. 'log4shell.json')."""
    path = FIXTURES_DIR / filename
    if not path.exists():
        return None
    raw = _populate_stage2_cves(_load_json(path))
    return FixtureResult(
        stage1=Stage1Result.model_validate(raw["stage1"]),
        stage2=Stage2Result.model_validate(raw["stage2"]),
        stage3=Stage3Result.model_validate(raw["stage3"]),
        verdict=RiskVerdict.model_validate(raw["verdict"]),
    )


def list_fixtures() -> list[dict]:
    """Return available demo scenarios (only those with fixture files present)."""
    available = []
    for s in DEMO_SCENARIOS:
        if (FIXTURES_DIR / s["file"]).exists():
            available.append(s)
    return available


def is_available(software: str, version: str) -> bool:
    key = f"{software.lower()}:{version}"
    if key not in _FIXTURE_INDEX:
        return False
    return (FIXTURES_DIR / _FIXTURE_INDEX[key]).exists()
