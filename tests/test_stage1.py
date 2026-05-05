"""
VAEL – Stage 1 Test Harness
Tests against known vulnerable software versions.

Run: pytest tests/test_stage1.py -v
  or: python tests/test_stage1.py   (no pytest needed)
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from core.cve_mapper import run_stage1
from core.version_utils import version_in_range, _normalize
from core.misconfig_mapper import get_misconfig_flags
from schemas.stage1 import Severity, CPEMatch


# ─────────────────────────────────────────────────────────────────
# Unit tests – version_utils (no network)
# ─────────────────────────────────────────────────────────────────
def test_version_normalization():
    assert _normalize("2.14.1") == (2, 14, 1)
    assert _normalize("1.0") == (1, 0)
    assert _normalize("10.0.0-beta")[:3] == (10, 0, 0)  # non-numeric suffix may append 0
    print("✓ version normalization")


def test_version_in_range_basic():
    match = CPEMatch(
        cpe23="cpe:2.3:a:*:log4j:*:*:*:*:*:*:*:*",
        version_start_including="2.0.0",
        version_end_excluding="2.17.1",
    )
    assert version_in_range("2.14.1", match) is True
    assert version_in_range("1.9.9", match) is False
    assert version_in_range("2.17.1", match) is False   # excluded
    assert version_in_range("2.17.0", match) is True
    print("✓ version_in_range basic")


def test_version_in_range_exact():
    match = CPEMatch(
        cpe23="cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
    )
    assert version_in_range("1.20.0", match) is True
    assert version_in_range("1.20.1", match) is False
    print("✓ version_in_range exact CPE")


def test_version_in_range_end_including():
    match = CPEMatch(
        cpe23="cpe:2.3:a:*:openssl:*:*:*:*:*:*:*:*",
        version_start_including="3.0.0",
        version_end_including="3.0.7",
    )
    assert version_in_range("3.0.7", match) is True
    assert version_in_range("3.0.8", match) is False
    print("✓ version_in_range end_including")


# ─────────────────────────────────────────────────────────────────
# Unit tests – misconfig_mapper (no network)
# ─────────────────────────────────────────────────────────────────
def test_misconfig_nginx():
    flags = get_misconfig_flags("nginx")
    assert len(flags) > 0
    sources = {f.source for f in flags}
    assert "CWE" in sources
    assert "CIS" in sources
    print(f"✓ misconfig nginx: {len(flags)} flags")


def test_misconfig_log4j():
    flags = get_misconfig_flags("log4j")
    crit = [f for f in flags if f.severity == Severity.CRITICAL]
    assert len(crit) > 0, "Expected CRITICAL misconfig for log4j"
    print(f"✓ misconfig log4j: {len(crit)} critical flags")


def test_misconfig_unknown():
    flags = get_misconfig_flags("totally_unknown_software_xyz")
    assert flags == []
    print("✓ misconfig unknown: empty list returned")


# ─────────────────────────────────────────────────────────────────
# Integration tests – live NVD/OSV calls
# Requires network. Skip by setting VAEL_SKIP_INTEGRATION=1
# ─────────────────────────────────────────────────────────────────
SKIP_INTEGRATION = os.getenv("VAEL_SKIP_INTEGRATION", "0") == "1"


@pytest.mark.integration
def test_stage1_log4j():
    """Log4Shell – should return CVE-2021-44228 with CRITICAL severity."""
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped (VAEL_SKIP_INTEGRATION=1)")
        return

    result = run_stage1("log4j", "2.14.1")

    assert result.total_cves > 0, "Expected CVEs for log4j 2.14.1"
    cve_ids = [c.cve_id for c in result.cves]
    assert "CVE-2021-44228" in cve_ids, f"Expected CVE-2021-44228, got: {cve_ids[:5]}"
    log4shell = next(c for c in result.cves if c.cve_id == "CVE-2021-44228")
    assert log4shell.cvss_v3 is not None
    assert log4shell.cvss_v3.severity == Severity.CRITICAL
    print(f"✓ log4j 2.14.1: {result.total_cves} CVEs, CVE-2021-44228 CRITICAL ✓")


@pytest.mark.integration
def test_stage1_nginx():
    """nginx 1.20.0 – should return at least CVE-2021-23017."""
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped")
        return

    result = run_stage1("nginx", "1.20.0")
    assert result.total_cves > 0, "Expected CVEs for nginx 1.20.0"
    print(f"✓ nginx 1.20.0: {result.total_cves} CVEs found")


@pytest.mark.integration
def test_stage1_osv_only():
    """Test with OSV only to verify offline-ish mode."""
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped")
        return

    result = run_stage1("django", "3.2.0", skip_nvd=True, osv_ecosystem="PyPI")
    assert "OSV" in result.sources_queried
    assert "NVD" not in result.sources_queried
    print(f"✓ django 3.2.0 (OSV only): {result.total_cves} CVEs")


@pytest.mark.integration
def test_stage1_json_serialization():
    """Verify Stage1Result can be serialized to JSON."""
    if SKIP_INTEGRATION:
        print("⊘ integration test skipped")
        return

    result = run_stage1("log4j", "2.14.1", skip_osv=True)
    json_str = result.model_dump_json()
    assert "CVE" in json_str or "cves" in json_str
    print("✓ JSON serialization works")


# ─────────────────────────────────────────────────────────────────
# Runner (no pytest needed)
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n═══ VAEL Stage 1 – Test Harness ═══\n")

    print("── Unit Tests (no network) ──")
    test_version_normalization()
    test_version_in_range_basic()
    test_version_in_range_exact()
    test_version_in_range_end_including()
    test_misconfig_nginx()
    test_misconfig_log4j()
    test_misconfig_unknown()

    print("\n── Integration Tests (network) ──")
    test_stage1_log4j()
    test_stage1_nginx()
    test_stage1_osv_only()
    test_stage1_json_serialization()

    print("\n✅ All tests passed.")
