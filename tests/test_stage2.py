"""
VAEL – Stage 2 Test Harness
Tests EPSS lookup, KEV lookup, patch detection, and VEP scoring.

Unit tests are offline (synthetic CVE data).
Integration tests hit live feeds — skip with VAEL_SKIP_INTEGRATION=1.

Run: python tests/test_stage2.py
"""

from __future__ import annotations

import sys
import os
from datetime import date

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from schemas.stage1 import (
    CVERecord, CVSSv3, Severity, CPEMatch, Reference, Stage1Result,
)
from schemas.stage2 import (
    EPSSEntry, KEVEntry, PatchInfo, VEPTier, ExploitMaturity,
)
from core.exploit_scorer import score_cve, infer_maturity
from core.patch_detector import detect_patch
from core.exploit_eval import run_stage2


# ────────────────────────────────────────────────────────────────────────
# Helper factories
# ────────────────────────────────────────────────────────────────────────
def _cve(
    cve_id="CVE-2021-TEST",
    cvss=9.5,
    version_matched=True,
    cpe_matches=None,
    refs=None,
) -> CVERecord:
    severity = Severity.CRITICAL if cvss >= 9.0 else (
        Severity.HIGH if cvss >= 7.0 else Severity.MEDIUM
    )
    return CVERecord(
        cve_id=cve_id,
        source="NVD",
        description=f"Test CVE {cve_id}",
        cvss_v3=CVSSv3(score=cvss, severity=severity),
        version_matched=version_matched,
        cpe_matches=cpe_matches or [],
        references=refs or [],
    )


def _epss(score=0.8, percentile=0.95) -> EPSSEntry:
    return EPSSEntry(cve_id="CVE-2021-TEST", epss=score, percentile=percentile,
                     score_date=date.today())


def _kev(cve_id="CVE-2021-TEST") -> KEVEntry:
    return KEVEntry(
        cve_id=cve_id,
        vendor_project="Apache", product="Log4j",
        vulnerability_name="Log4Shell",
        date_added=date(2021, 12, 10),
        required_action="Apply updates per vendor instructions.",
    )


# ────────────────────────────────────────────────────────────────────────
# Unit tests — maturity inference
# ────────────────────────────────────────────────────────────────────────
def test_maturity_kev_wins():
    assert infer_maturity(in_kev=True, epss=_epss(0.01)) == ExploitMaturity.WEAPONIZED
    print("✓ KEV → WEAPONIZED")


def test_maturity_high_epss():
    assert infer_maturity(in_kev=False, epss=_epss(0.6)) == ExploitMaturity.FUNCTIONAL
    print("✓ EPSS 0.6 → FUNCTIONAL")


def test_maturity_mid_epss():
    assert infer_maturity(in_kev=False, epss=_epss(0.15)) == ExploitMaturity.PROOF_OF_CONCEPT
    print("✓ EPSS 0.15 → PROOF_OF_CONCEPT")


def test_maturity_no_data():
    assert infer_maturity(in_kev=False, epss=None) == ExploitMaturity.UNKNOWN
    print("✓ No data → UNKNOWN")


def test_maturity_unproven():
    assert infer_maturity(in_kev=False, epss=_epss(0.001)) == ExploitMaturity.UNPROVEN
    print("✓ EPSS < 0.01 → UNPROVEN")


# ────────────────────────────────────────────────────────────────────────
# Unit tests — VEP scoring
# ────────────────────────────────────────────────────────────────────────
def test_score_kev_version_matched_is_t0():
    cve = _cve(cvss=10.0, version_matched=True)
    result = score_cve(cve, epss=_epss(0.975), kev_entry=_kev(),
                       patch=PatchInfo(patch_available=True, fixed_versions=["2.17.1"]))
    assert result.vep_tier == VEPTier.T0_PATCH_NOW, f"Expected T0, got {result.vep_tier}"
    assert result.vep_score >= 70, f"Expected high score, got {result.vep_score}"
    assert result.in_kev is True
    print(f"✓ KEV+matched+CVSS10 → T0 (score={result.vep_score})")


def test_score_kev_not_matched_is_t1():
    cve = _cve(cvss=9.0, version_matched=False)
    result = score_cve(cve, epss=_epss(0.9), kev_entry=_kev())
    assert result.vep_tier == VEPTier.T1_HIGH, f"Expected T1, got {result.vep_tier}"
    print(f"✓ KEV+NOT matched → T1 (score={result.vep_score})")


def test_score_critical_no_exploit_is_monitor():
    cve = _cve(cvss=9.8, version_matched=True)
    result = score_cve(cve, epss=_epss(0.02, 0.3), kev_entry=None,
                       patch=PatchInfo(patch_available=True))
    # CVSS 9.8×3 = 29.4, EPSS 0.02×40 = 0.8 → ~30, matches T2 MONITOR
    assert result.vep_tier in (VEPTier.T2_MONITOR, VEPTier.T1_HIGH)
    print(f"✓ Critical CVSS, no exploit → {result.vep_tier.value} (score={result.vep_score})")


def test_score_low_everything_is_defer():
    cve = _cve(cvss=4.0, version_matched=False)
    result = score_cve(cve, epss=_epss(0.001, 0.1))
    assert result.vep_tier in (VEPTier.T3_DEFER, VEPTier.T_UNKNOWN)
    print(f"✓ Low CVSS + no exploit → {result.vep_tier.value} (score={result.vep_score})")


def test_score_reasoning_populated():
    cve = _cve()
    result = score_cve(cve, epss=_epss(), kev_entry=_kev())
    assert len(result.reasoning) >= 4, f"Expected >=4 reasoning bullets, got {len(result.reasoning)}"
    assert any("CVSS" in r for r in result.reasoning)
    assert any("EPSS" in r for r in result.reasoning)
    assert any("KEV" in r for r in result.reasoning)
    print(f"✓ Reasoning populated: {len(result.reasoning)} bullets")


def test_score_no_version_match_dampens_score():
    cve_matched = _cve(cvss=9.0, version_matched=True)
    cve_unmatched = _cve(cvss=9.0, version_matched=False)
    result_matched = score_cve(cve_matched, epss=_epss(0.8))
    result_unmatched = score_cve(cve_unmatched, epss=_epss(0.8))
    assert result_matched.vep_score > result_unmatched.vep_score
    print(f"✓ Version-matched dampening: {result_matched.vep_score} > {result_unmatched.vep_score}")


# ────────────────────────────────────────────────────────────────────────
# Unit tests — patch detection
# ────────────────────────────────────────────────────────────────────────
def test_patch_from_cpe_range():
    cve = _cve(cpe_matches=[
        CPEMatch(cpe23="cpe:2.3:a:*:log4j:*", version_end_excluding="2.17.1")
    ])
    info = detect_patch(cve)
    assert info.patch_available is True
    assert "2.17.1" in info.fixed_versions
    print("✓ Patch derived from CPE range")


def test_patch_from_references():
    cve = _cve(refs=[
        Reference(url="https://logging.apache.org/log4j/2.x/security.html",
                  tags=["Vendor Advisory", "Patch"]),
        Reference(url="https://github.com/apache/logging-log4j2/releases",
                  tags=["Release Notes"]),
    ])
    info = detect_patch(cve)
    assert info.patch_available is True
    assert info.vendor_advisory_url is not None
    assert len(info.patch_urls) >= 1
    print(f"✓ Patch from refs: {len(info.patch_urls)} URLs")


def test_patch_none_available():
    cve = _cve(refs=[
        Reference(url="https://example.com/blog/research", tags=["Third Party"])
    ])
    info = detect_patch(cve)
    assert info.patch_available is False
    print("✓ No patch signals → patch_available=False")


# ────────────────────────────────────────────────────────────────────────
# Unit tests — Stage 2 orchestrator (offline, with synthetic Stage 1)
# ────────────────────────────────────────────────────────────────────────
def test_stage2_offline_synthetic():
    """Run Stage 2 against synthetic Stage 1 data, no network."""
    s1 = Stage1Result(software="log4j", version="2.14.1")
    s1.cves = [
        _cve(cve_id="CVE-FAKE-001", cvss=10.0, version_matched=True),
        _cve(cve_id="CVE-FAKE-002", cvss=5.0, version_matched=False),
    ]
    s1.compute_summary()

    s2 = run_stage2(s1, allow_network=False)

    assert s2.software == "log4j"
    assert len(s2.enrichments) == 2
    assert all(e.vep_tier is not None for e in s2.enrichments)
    # Even with no EPSS/KEV data, scoring still produces tiers
    print(f"✓ Stage 2 offline orchestration works — tiers assigned: "
          f"{[e.vep_tier.value for e in s2.enrichments]}")


# ────────────────────────────────────────────────────────────────────────
# Integration tests — live EPSS/KEV feeds
# ────────────────────────────────────────────────────────────────────────
SKIP_INTEGRATION = os.getenv("VAEL_SKIP_INTEGRATION", "0") == "1"


@pytest.mark.integration
def test_kev_log4shell_live():
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped")
        return
    from core.kev_fetcher import lookup_kev
    result = lookup_kev(["CVE-2021-44228"])
    entry = result.get("CVE-2021-44228")
    assert entry is not None, "Log4Shell should be in CISA KEV"
    assert "Log4j" in (entry.product or "") or "Log4j" in (entry.vulnerability_name or "")
    print(f"✓ KEV live: CVE-2021-44228 = {entry.vulnerability_name}")


@pytest.mark.integration
def test_epss_log4shell_live():
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped")
        return
    from core.epss_fetcher import lookup_epss
    result = lookup_epss(["CVE-2021-44228"])
    entry = result.get("CVE-2021-44228")
    assert entry is not None, "Log4Shell should have EPSS"
    assert entry.epss > 0.5, f"Expected high EPSS for Log4Shell, got {entry.epss}"
    print(f"✓ EPSS live: CVE-2021-44228 = {entry.epss:.3f} (p{entry.percentile*100:.1f})")


@pytest.mark.integration
def test_full_pipeline_log4j():
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped")
        return
    from core.cve_mapper import run_stage1
    s1 = run_stage1("log4j", "2.14.1")
    s2 = run_stage2(s1, allow_network=True)

    assert s2.kev_count >= 1, "Expected at least 1 KEV entry for log4j 2.14.1"
    assert s2.t0_patch_now_count >= 1, "Expected at least 1 T0 tier"

    top_cve, top_enrichment = s2.top_priority_cves(1)[0]
    assert top_enrichment.vep_tier == VEPTier.T0_PATCH_NOW
    print(f"✓ Full pipeline: top-priority = {top_cve.cve_id} ({top_enrichment.vep_tier.value})")


# ────────────────────────────────────────────────────────────────────────
# Runner
# ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n═══ VAEL Stage 2 – Test Harness ═══\n")

    print("── Maturity Inference ──")
    test_maturity_kev_wins()
    test_maturity_high_epss()
    test_maturity_mid_epss()
    test_maturity_no_data()
    test_maturity_unproven()

    print("\n── VEP Scoring ──")
    test_score_kev_version_matched_is_t0()
    test_score_kev_not_matched_is_t1()
    test_score_critical_no_exploit_is_monitor()
    test_score_low_everything_is_defer()
    test_score_reasoning_populated()
    test_score_no_version_match_dampens_score()

    print("\n── Patch Detection ──")
    test_patch_from_cpe_range()
    test_patch_from_references()
    test_patch_none_available()

    print("\n── Stage 2 Orchestrator (offline) ──")
    test_stage2_offline_synthetic()

    print("\n── Integration (live feeds) ──")
    test_kev_log4shell_live()
    test_epss_log4shell_live()
    test_full_pipeline_log4j()

    print("\n✅ All Stage 2 tests passed.")
