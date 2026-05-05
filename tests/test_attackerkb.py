"""
Tests for core/attackerkb_fetcher.py — Rapid7 AttackerKB integration.
All tests are offline; HTTP calls are mocked.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from core.attackerkb_fetcher import _parse_topic, fetch_attackerkb
from core.utils import severity_from_score as _severity
from schemas.stage1 import Severity


# ── _severity mapping ─────────────────────────────────────────────────────────

def test_severity_critical():
    assert _severity(10.0) == Severity.CRITICAL
    assert _severity(9.0) == Severity.CRITICAL


def test_severity_high():
    assert _severity(8.5) == Severity.HIGH
    assert _severity(7.0) == Severity.HIGH


def test_severity_medium():
    assert _severity(6.9) == Severity.MEDIUM
    assert _severity(4.0) == Severity.MEDIUM


def test_severity_low():
    assert _severity(3.9) == Severity.LOW
    assert _severity(0.1) == Severity.LOW


def test_severity_none():
    assert _severity(0.0) == Severity.NONE


def test_severity_unknown():
    assert _severity(None) == Severity.UNKNOWN


# ── _parse_topic ──────────────────────────────────────────────────────────────

def _make_topic(**overrides):
    base = {
        "name": "CVE-2021-44228",
        "document": {
            "description": "Log4Shell remote code execution",
            "references": [{"url": "https://example.com/ref"}],
        },
        "metadata": {
            "nvdScore": 10.0,
        },
    }
    base.update(overrides)
    return base


def test_parse_topic_extracts_cve_id():
    rec = _parse_topic(_make_topic())
    assert rec is not None
    assert rec.cve_id == "CVE-2021-44228"


def test_parse_topic_sets_source():
    rec = _parse_topic(_make_topic())
    assert rec.source == "ATTACKERKB"


def test_parse_topic_cvss_score():
    rec = _parse_topic(_make_topic())
    assert rec.cvss_v3 is not None
    assert rec.cvss_v3.score == 10.0
    assert rec.cvss_v3.severity == Severity.CRITICAL


def test_parse_topic_non_cve_returns_none():
    rec = _parse_topic({"name": "GHSA-xxxx-yyyy-zzzz", "document": {}, "metadata": {}})
    assert rec is None


def test_parse_topic_lowercase_name_normalised():
    rec = _parse_topic(_make_topic(name="cve-2021-44228"))
    assert rec is not None
    assert rec.cve_id == "CVE-2021-44228"


def test_parse_topic_missing_cvss_is_none():
    topic = {"name": "CVE-2020-1234", "document": {}, "metadata": {}}
    rec = _parse_topic(topic)
    assert rec is not None
    assert rec.cvss_v3 is None


def test_parse_topic_description_extracted():
    rec = _parse_topic(_make_topic())
    assert rec.description == "Log4Shell remote code execution"


def test_parse_topic_references_extracted():
    rec = _parse_topic(_make_topic())
    assert len(rec.references) == 1
    assert rec.references[0].url == "https://example.com/ref"


def test_parse_topic_missing_document_fields():
    topic = {"name": "CVE-2020-9999"}
    rec = _parse_topic(topic)
    assert rec is not None
    assert rec.cve_id == "CVE-2020-9999"


# ── fetch_attackerkb ──────────────────────────────────────────────────────────

def test_fetch_no_key_returns_empty():
    recs, errors = fetch_attackerkb("log4j", "2.14.1", api_key=None)
    assert recs == []
    assert errors == []


def test_fetch_mocked_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.json.return_value = {
        "data": [
            {
                "name": "CVE-2021-44228",
                "document": {"description": "Log4Shell"},
                "metadata": {"nvdScore": 10.0},
            }
        ]
    }

    with patch("core.attackerkb_fetcher.http_client") as mock_hc, \
         patch("core.attackerkb_fetcher._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.api.get.return_value = mock_resp
        recs, errors = fetch_attackerkb("log4j", "2.14.1", api_key="test_key")

    assert len(recs) == 1
    assert recs[0].cve_id == "CVE-2021-44228"
    assert errors == []


def test_fetch_mocked_401_returns_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.is_success = False
    mock_resp.headers = {}

    with patch("core.attackerkb_fetcher.http_client") as mock_hc, \
         patch("core.attackerkb_fetcher._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.api.get.return_value = mock_resp
        recs, errors = fetch_attackerkb("log4j", "2.14.1", api_key="bad_key")

    assert recs == []
    assert any("401" in e or "invalid" in e.lower() for e in errors)


def test_fetch_mocked_429_returns_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.is_success = False
    mock_resp.headers = {}

    with patch("core.attackerkb_fetcher.http_client") as mock_hc, \
         patch("core.attackerkb_fetcher._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.api.get.return_value = mock_resp
        recs, errors = fetch_attackerkb("log4j", "2.14.1", api_key="real_key")

    assert recs == []
    assert any("RateLimit" in e or "429" in e or "rate" in e.lower() for e in errors)
