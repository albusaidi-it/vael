"""
VAEL – Stage 3 & AI Reasoner Test Harness

Run: python tests/test_stage3.py
"""

from __future__ import annotations

import sys
import os
from datetime import date
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from schemas.stage1 import CVERecord, CVSSv3, Severity, Stage1Result
from schemas.stage2 import (
    Stage2Result, ExploitabilityEnrichment, VEPTier,
    ExploitMaturity, EPSSEntry, KEVEntry, PatchInfo,
)
from schemas.stage3 import (
    Stage3Result, CVEPoCBundle, PoCRecord, PoCSource, PoCQuality,
    VersionCompatibility,
)

from core.github_harvester import (
    _is_likely_fake, _classify_quality, _check_version_compatibility,
)
from core.poc_harvester import (
    _deduplicate, _sort_pocs, update_stage2_maturity,
)
from core.ai_reasoner import (
    _deterministic_verdict, _build_prompt, _parse_gemini_response,
    build_verdict, RiskVerdict,
)


# ────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────
def _poc(cve_id="CVE-X", source=PoCSource.GITHUB, url="https://example/a",
         quality=PoCQuality.FUNCTIONAL, compat=VersionCompatibility.CONFIRMED,
         stars=5, author="researcher"):
    return PoCRecord(
        cve_id=cve_id, source=source, url=url,
        quality=quality, version_compatibility=compat,
        stars=stars, author=author, title="test",
    )


def _cve(cve_id="CVE-2021-44228", cvss=10.0, matched=True):
    return CVERecord(
        cve_id=cve_id, source="NVD",
        description=f"Test CVE {cve_id}",
        cvss_v3=CVSSv3(score=cvss, severity=Severity.CRITICAL),
        version_matched=matched,
    )


# ────────────────────────────────────────────────────────────────────────
# GitHub classifier tests
# ────────────────────────────────────────────────────────────────────────
def test_fake_detection_empty_desc():
    assert _is_likely_fake("log4shell-poc", None) is True
    assert _is_likely_fake("log4shell-poc", "") is True
    print("✓ Empty description → fake")


def test_fake_detection_awesome_list():
    assert _is_likely_fake("awesome-log4shell", "A curated list") is True
    assert _is_likely_fake("awesome-cve-list", "Collection of CVEs") is True
    print("✓ 'Awesome' lists flagged as fake")


def test_fake_detection_raw_cve_name():
    assert _is_likely_fake("CVE-2021-44228", "Short") is True
    print("✓ Bare CVE ID names flagged as fake")


def test_fake_detection_legitimate_repo():
    assert _is_likely_fake(
        "log4j-exploit-poc",
        "Working PoC for CVE-2021-44228 including JNDI lookup via LDAP server"
    ) is False
    print("✓ Legitimate description not flagged")


def test_classify_quality_trusted_author():
    repo = {"name": "metasploit-framework", "description": "exploit framework",
            "owner": {"login": "rapid7"}, "stargazers_count": 30000, "size": 5000}
    q = _classify_quality(repo, has_readme=True, readme_text="full exploit code")
    assert q == PoCQuality.WEAPONIZED
    print("✓ Trusted author → WEAPONIZED")


def test_classify_quality_nuclei_in_name():
    repo = {"name": "nuclei-template-log4j", "description": "nuclei template",
            "owner": {"login": "anonymous"}, "stargazers_count": 5, "size": 2}
    q = _classify_quality(repo, has_readme=True, readme_text="")
    assert q == PoCQuality.WEAPONIZED
    print("✓ Nuclei template → WEAPONIZED")


def test_classify_quality_functional_poc():
    repo = {"name": "log4j-poc", "description": "Working PoC for Log4Shell",
            "owner": {"login": "researcher"}, "stargazers_count": 50, "size": 20}
    readme = "This is a proof-of-concept exploit for CVE-2021-44228 using JNDI LDAP."
    q = _classify_quality(repo, has_readme=True, readme_text=readme)
    assert q == PoCQuality.FUNCTIONAL
    print("✓ Working exploit + stars → FUNCTIONAL")


def test_classify_quality_fake_repo():
    repo = {"name": "CVE-2021-44228", "description": "",
            "owner": {"login": "spam"}, "stargazers_count": 0, "size": 0}
    q = _classify_quality(repo, has_readme=False, readme_text="")
    assert q == PoCQuality.FAKE
    print("✓ Spam repo → FAKE")


# ────────────────────────────────────────────────────────────────────────
# Version compatibility tests
# ────────────────────────────────────────────────────────────────────────
def test_version_compat_confirmed():
    compat, versions = _check_version_compatibility(
        "2.14.1",
        "This PoC targets log4j 2.14.1 specifically.",
        "",
    )
    assert compat == VersionCompatibility.CONFIRMED
    assert "2.14.1" in versions
    print("✓ Target version in text → CONFIRMED")


def test_version_compat_likely_range():
    compat, versions = _check_version_compatibility(
        "2.14.1",
        "Affects versions 2.0.0 through 2.16.0",
        "",
    )
    assert compat == VersionCompatibility.LIKELY
    print(f"✓ Version range → LIKELY (detected: {versions})")


def test_version_compat_unknown():
    compat, versions = _check_version_compatibility(
        "2.14.1", "Generic exploit README with no version info.", "",
    )
    assert compat == VersionCompatibility.UNKNOWN
    print("✓ No version info → UNKNOWN")


# ────────────────────────────────────────────────────────────────────────
# Deduplication & sorting tests
# ────────────────────────────────────────────────────────────────────────
def test_dedup_same_url_keeps_best_quality():
    pocs = [
        _poc(url="https://x/a", quality=PoCQuality.CONCEPTUAL),
        _poc(url="https://x/a", quality=PoCQuality.WEAPONIZED),
        _poc(url="https://x/b", quality=PoCQuality.FUNCTIONAL),
    ]
    deduped = _deduplicate(pocs)
    assert len(deduped) == 2
    by_url = {p.url: p for p in deduped}
    assert by_url["https://x/a"].quality == PoCQuality.WEAPONIZED
    print("✓ Dedup keeps best quality")


def test_sort_by_quality_then_compat_then_stars():
    pocs = [
        _poc(url="1", quality=PoCQuality.CONCEPTUAL, compat=VersionCompatibility.CONFIRMED, stars=100),
        _poc(url="2", quality=PoCQuality.WEAPONIZED, compat=VersionCompatibility.UNKNOWN,   stars=1),
        _poc(url="3", quality=PoCQuality.FUNCTIONAL, compat=VersionCompatibility.CONFIRMED, stars=50),
    ]
    sorted_pocs = _sort_pocs(pocs)
    # Weaponized first, then functional (with stars), then conceptual
    assert sorted_pocs[0].quality == PoCQuality.WEAPONIZED
    assert sorted_pocs[1].quality == PoCQuality.FUNCTIONAL
    assert sorted_pocs[2].quality == PoCQuality.CONCEPTUAL
    print("✓ Sorting by quality → compat → stars")


# ────────────────────────────────────────────────────────────────────────
# Bundle aggregation tests
# ────────────────────────────────────────────────────────────────────────
def test_bundle_aggregate_best_quality():
    bundle = CVEPoCBundle(cve_id="CVE-X", pocs=[
        _poc(quality=PoCQuality.CONCEPTUAL, compat=VersionCompatibility.UNKNOWN),
        _poc(quality=PoCQuality.WEAPONIZED, compat=VersionCompatibility.CONFIRMED),
        _poc(quality=PoCQuality.FUNCTIONAL, compat=VersionCompatibility.LIKELY),
    ])
    bundle.compute_aggregate()
    assert bundle.best_quality == PoCQuality.WEAPONIZED
    assert bundle.total_found == 3
    assert bundle.compatible_pocs_count == 2    # CONFIRMED + LIKELY
    print(f"✓ Bundle aggregates: best={bundle.best_quality.value}, compat={bundle.compatible_pocs_count}")


# ────────────────────────────────────────────────────────────────────────
# Stage 2 feedback tests
# ────────────────────────────────────────────────────────────────────────
def test_maturity_upgrade_weaponized():
    s2 = Stage2Result(software="log4j", version="2.14.1")
    s2.enrichments = [ExploitabilityEnrichment(
        cve_id="CVE-2021-44228",
        exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT,
    )]

    bundle = CVEPoCBundle(cve_id="CVE-2021-44228", pocs=[
        _poc(quality=PoCQuality.WEAPONIZED, compat=VersionCompatibility.CONFIRMED),
    ])
    bundle.compute_aggregate()

    s3 = Stage3Result(software="log4j", version="2.14.1", bundles=[bundle])
    s3.compute_summary()

    update_stage2_maturity(s2, s3)
    assert s2.enrichments[0].exploit_maturity == ExploitMaturity.WEAPONIZED
    print("✓ Stage 3 weaponized PoC upgrades Stage 2 maturity")


def test_maturity_no_downgrade():
    """If Stage 3 finds only CONCEPTUAL PoCs but Stage 2 already had WEAPONIZED from KEV, don't downgrade."""
    s2 = Stage2Result(software="x", version="1.0")
    s2.enrichments = [ExploitabilityEnrichment(
        cve_id="CVE-X",
        exploit_maturity=ExploitMaturity.WEAPONIZED,  # Already top
    )]

    bundle = CVEPoCBundle(cve_id="CVE-X", pocs=[
        _poc(quality=PoCQuality.CONCEPTUAL, compat=VersionCompatibility.UNKNOWN),
    ])
    bundle.compute_aggregate()
    s3 = Stage3Result(software="x", version="1.0", bundles=[bundle])

    update_stage2_maturity(s2, s3)
    assert s2.enrichments[0].exploit_maturity == ExploitMaturity.WEAPONIZED
    print("✓ Never downgrade maturity level")


# ────────────────────────────────────────────────────────────────────────
# Deterministic verdict tests
# ────────────────────────────────────────────────────────────────────────
def test_deterministic_verdict_t0():
    s2 = Stage2Result(software="log4j", version="2.14.1")
    s2.stage1_cves = [_cve("CVE-2021-44228", cvss=10.0, matched=True)]
    s2.enrichments = [ExploitabilityEnrichment(
        cve_id="CVE-2021-44228", vep_tier=VEPTier.T0_PATCH_NOW,
        vep_score=100.0, in_kev=True,
        kev_entry=KEVEntry(cve_id="CVE-2021-44228", vulnerability_name="Log4Shell",
                           date_added=date(2021, 12, 10)),
        epss=EPSSEntry(cve_id="CVE-2021-44228", epss=0.975, percentile=0.999),
    )]
    v = _deterministic_verdict(s2)
    assert v.label == "PATCH NOW"
    assert v.used_ai is False
    assert "KEV" in " ".join(v.key_evidence)
    assert "CVE-2021-44228" in v.reasoning_summary
    print(f"✓ Deterministic T0 verdict: {v.label} (conf={v.confidence})")


def test_deterministic_verdict_defer_no_cves():
    s2 = Stage2Result(software="safe-app", version="99.99")
    v = _deterministic_verdict(s2)
    assert v.label == "DEFER"
    assert v.used_ai is False
    print("✓ No CVEs → DEFER verdict")


# ────────────────────────────────────────────────────────────────────────
# Gemini prompt / parsing tests
# ────────────────────────────────────────────────────────────────────────
def test_prompt_contains_all_key_facts():
    s1 = Stage1Result(software="log4j", version="2.14.1")
    s1.cves = [_cve()]
    s1.compute_summary()
    s2 = Stage2Result(software="log4j", version="2.14.1", stage1_cves=s1.cves)
    s2.enrichments = [ExploitabilityEnrichment(
        cve_id="CVE-2021-44228", vep_tier=VEPTier.T0_PATCH_NOW,
        vep_score=100.0, in_kev=True,
        epss=EPSSEntry(cve_id="CVE-2021-44228", epss=0.975, percentile=0.999),
    )]

    prompt = _build_prompt(s1, s2)
    assert "log4j" in prompt
    assert "2.14.1" in prompt
    assert "CVE-2021-44228" in prompt
    assert "CISA KEV" in prompt or "IN CISA KEV" in prompt
    assert "OUTPUT SCHEMA" in prompt
    assert "Do not retrieve or invent" in prompt
    print("✓ Prompt contains all key facts and safety instructions")


def test_parse_valid_gemini_response():
    raw = '''{"label": "PATCH NOW",
              "recommendation": "Patch within 7 days.",
              "confidence": 0.95,
              "reasoning_summary": "Critical vuln.",
              "key_evidence": ["EPSS 0.975", "In KEV"]}'''
    v = _parse_gemini_response(raw)
    assert v is not None
    assert v.label == "PATCH NOW"
    assert v.confidence == 0.95
    assert len(v.key_evidence) == 2
    print("✓ Valid JSON response parses correctly")


def test_parse_gemini_with_markdown_fences():
    raw = '''```json
{"label": "HIGH", "recommendation": "Patch soon.", "confidence": 0.8,
 "reasoning_summary": "Medium risk.", "key_evidence": []}
```'''
    v = _parse_gemini_response(raw)
    assert v is not None
    assert v.label == "HIGH"
    print("✓ Markdown-fenced JSON parses correctly")


def test_parse_invalid_label_rejected():
    raw = '{"label": "INVALID_LABEL", "recommendation": "", "confidence": 0.5, "reasoning_summary": "", "key_evidence": []}'
    v = _parse_gemini_response(raw)
    assert v is None
    print("✓ Invalid label rejected")


def test_parse_malformed_json_rejected():
    raw = "This is not JSON at all"
    v = _parse_gemini_response(raw)
    assert v is None
    print("✓ Non-JSON response rejected")


def test_build_verdict_falls_back_without_key():
    s1 = Stage1Result(software="x", version="1.0")
    s2 = Stage2Result(software="x", version="1.0")
    v = build_verdict(s1, s2, gemini_api_key=None, force_deterministic=False)
    # No key → should fall back deterministic
    assert v.used_ai is False
    print("✓ No API key → deterministic fallback")


def test_build_verdict_force_deterministic():
    s1 = Stage1Result(software="x", version="1.0")
    s2 = Stage2Result(software="x", version="1.0")
    v = build_verdict(s1, s2, gemini_api_key="fake_key",
                      force_deterministic=True)
    assert v.used_ai is False
    print("✓ force_deterministic=True → no Gemini call")


# ────────────────────────────────────────────────────────────────────────
# Runner
# ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n═══ VAEL Stage 3 + AI Reasoner Test Harness ═══\n")

    print("── GitHub Classifier ──")
    test_fake_detection_empty_desc()
    test_fake_detection_awesome_list()
    test_fake_detection_raw_cve_name()
    test_fake_detection_legitimate_repo()
    test_classify_quality_trusted_author()
    test_classify_quality_nuclei_in_name()
    test_classify_quality_functional_poc()
    test_classify_quality_fake_repo()

    print("\n── Version Compatibility ──")
    test_version_compat_confirmed()
    test_version_compat_likely_range()
    test_version_compat_unknown()

    print("\n── Deduplication & Sorting ──")
    test_dedup_same_url_keeps_best_quality()
    test_sort_by_quality_then_compat_then_stars()

    print("\n── Bundle Aggregation ──")
    test_bundle_aggregate_best_quality()

    print("\n── Stage 2 Feedback ──")
    test_maturity_upgrade_weaponized()
    test_maturity_no_downgrade()

    print("\n── Deterministic Verdict ──")
    test_deterministic_verdict_t0()
    test_deterministic_verdict_defer_no_cves()

    print("\n── Gemini Prompt & Parsing ──")
    test_prompt_contains_all_key_facts()
    test_parse_valid_gemini_response()
    test_parse_gemini_with_markdown_fences()
    test_parse_invalid_label_rejected()
    test_parse_malformed_json_rejected()
    test_build_verdict_falls_back_without_key()
    test_build_verdict_force_deterministic()

    print("\n✅ All Stage 3 + AI Reasoner tests passed.")
