"""
Tests for core/name_resolver.py — software name canonicalisation.
All tests are offline (reads local YAML alias file only).
"""
from __future__ import annotations

import pytest
from core.name_resolver import resolve, _normalise, _clean_version, ResolvedName


# ── _normalise ────────────────────────────────────────────────────────────────

def test_normalise_strips_punctuation():
    assert _normalise("Apache Log4J") == "apachelog4j"
    assert _normalise("spring-boot") == "springboot"
    assert _normalise("node.js") == "nodejs"


def test_normalise_collapses_whitespace():
    assert _normalise("  log4j  core  ") == "log4jcore"


# ── _clean_version ────────────────────────────────────────────────────────────

def test_clean_version_strips_v_prefix():
    assert _clean_version("v2.14.1") == "2.14.1"
    assert _clean_version("V1.0.0") == "1.0.0"


def test_clean_version_strips_snapshot():
    assert _clean_version("2.14.1-SNAPSHOT") == "2.14.1"
    assert _clean_version("3.0.0.RELEASE") == "3.0.0"


def test_clean_version_strips_rc():
    result = _clean_version("2.0.0-RC1")
    assert result.startswith("2.0.0")


def test_clean_version_plain_passthrough():
    assert _clean_version("2.14.1") == "2.14.1"


# ── resolve ───────────────────────────────────────────────────────────────────

def test_resolve_returns_resolved_name():
    result = resolve("log4j", "2.14.1")
    assert isinstance(result, ResolvedName)
    assert result.input_software == "log4j"
    assert result.clean_version == "2.14.1"


def test_resolve_known_alias_log4j():
    result = resolve("log4j2", "2.14.1")
    assert result.canonical_name is not None
    assert result.match_method != "none"


def test_resolve_nginx():
    result = resolve("nginx", "1.20.0")
    assert result.canonical_name is not None
    assert result.cpe_vendor is not None


def test_resolve_unknown_software_fallback():
    result = resolve("totally_unknown_software_xyz_12345", "1.0.0")
    assert result.canonical_name == "totally_unknown_software_xyz_12345"
    assert result.match_method in ("none", "fallback")


def test_resolve_version_cleaned():
    result = resolve("log4j", "v2.14.1-SNAPSHOT")
    assert result.clean_version == "2.14.1"


def test_resolve_ecosystem_pypi():
    result = resolve("django", "3.2.0")
    if result.ecosystem:
        assert result.ecosystem.upper() in ("PYPI", "PYTHON")


def test_cpe_string_format():
    result = resolve("log4j", "2.14.1")
    cpe = result.cpe_string()
    if cpe:
        assert cpe.startswith("cpe:2.3:a:")
        assert "2.14.1" in cpe
