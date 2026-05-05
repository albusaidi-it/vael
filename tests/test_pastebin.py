"""
Tests for core/pastebin_harvester.py — Pastebin PoC scraper.
All tests are offline; HTTP calls are mocked.
"""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from core.pastebin_harvester import _classify, search_pastebin
from schemas.stage3 import PoCQuality


# ── _classify ─────────────────────────────────────────────────────────────────

def test_classify_exploit_keywords():
    assert _classify("log4j exploit shell") == PoCQuality.FUNCTIONAL
    assert _classify("RCE payload") == PoCQuality.FUNCTIONAL
    assert _classify("reverse shell CVE") == PoCQuality.FUNCTIONAL
    assert _classify("remote code execution PoC") == PoCQuality.FUNCTIONAL


def test_classify_poc_keywords():
    assert _classify("proof of concept bypass") == PoCQuality.CONCEPTUAL
    assert _classify("poc injection script") == PoCQuality.CONCEPTUAL
    assert _classify("vulnerability disclosure") == PoCQuality.CONCEPTUAL


def test_classify_unknown_no_keywords():
    assert _classify("random paste content") == PoCQuality.UNKNOWN
    assert _classify("") == PoCQuality.UNKNOWN
    assert _classify("   ") == PoCQuality.UNKNOWN


def test_classify_functional_takes_priority_over_conceptual():
    # "exploit" (functional) and "poc" (conceptual) in same string → FUNCTIONAL wins
    assert _classify("exploit poc script") == PoCQuality.FUNCTIONAL


def test_classify_case_insensitive():
    assert _classify("EXPLOIT code") == PoCQuality.FUNCTIONAL
    assert _classify("Proof Of Concept") == PoCQuality.CONCEPTUAL


def test_classify_uses_snippet_too():
    assert _classify("title", "reverse shell working exploit") == PoCQuality.FUNCTIONAL


# ── search_pastebin ───────────────────────────────────────────────────────────

def test_search_offline_returns_empty():
    pocs, errors = search_pastebin("CVE-2021-44228", "2.14.1", allow_network=False)
    assert pocs == []
    assert errors == []


def test_search_mocked_success():
    html = """
    <html><body>
      <a href="/AbCdEfGh">CVE-2021-44228 exploit shell</a>
      <a href="/XyZ12345">CVE-2021-44228 proof of concept</a>
    </body></html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.text = html

    with patch("core.pastebin_harvester.http_client") as mock_hc, \
         patch("core.pastebin_harvester._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.scrape.get.return_value = mock_resp
        pocs, errors = search_pastebin("CVE-2021-44228", "2.14.1")

    assert len(pocs) == 2
    urls = [p.url for p in pocs]
    assert "https://pastebin.com/AbCdEfGh" in urls
    assert "https://pastebin.com/XyZ12345" in urls
    assert errors == []


def test_search_mocked_filters_non_cve_results():
    # Paste that does not mention the CVE should be filtered out
    html = """
    <html><body>
      <a href="/AbCdEfGh">totally unrelated python script</a>
    </body></html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.text = html

    with patch("core.pastebin_harvester.http_client") as mock_hc, \
         patch("core.pastebin_harvester._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.scrape.get.return_value = mock_resp
        pocs, errors = search_pastebin("CVE-2021-44228", "2.14.1")

    assert pocs == []


def test_search_mocked_429_returns_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_resp.is_success = False
    mock_resp.headers = {}

    with patch("core.pastebin_harvester.http_client") as mock_hc, \
         patch("core.pastebin_harvester._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.scrape.get.return_value = mock_resp
        pocs, errors = search_pastebin("CVE-2021-44228", "2.14.1")

    assert pocs == []
    assert any("RateLimit" in e or "429" in e for e in errors)


def test_search_mocked_skips_non_paste_paths():
    # /search and /login hrefs must not become PoC records
    html = """
    <html><body>
      <a href="/search">Search</a>
      <a href="/login">Login</a>
      <a href="/u/someuser">Profile</a>
      <a href="/AbCdEfGh">CVE-2021-44228 exploit</a>
    </body></html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.text = html

    with patch("core.pastebin_harvester.http_client") as mock_hc, \
         patch("core.pastebin_harvester._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.scrape.get.return_value = mock_resp
        pocs, errors = search_pastebin("CVE-2021-44228", "2.14.1")

    assert len(pocs) == 1
    assert pocs[0].url == "https://pastebin.com/AbCdEfGh"


def test_search_source_is_pastebin():
    from schemas.stage3 import PoCSource
    html = '<html><body><a href="/AbCdEfGh">CVE-2021-44228 exploit rce</a></body></html>'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.headers = {}
    mock_resp.text = html

    with patch("core.pastebin_harvester.http_client") as mock_hc, \
         patch("core.pastebin_harvester._cache_mod") as mock_cache:
        mock_cache.get.return_value = None
        mock_hc.scrape.get.return_value = mock_resp
        pocs, _ = search_pastebin("CVE-2021-44228", "2.14.1")

    assert pocs[0].source == PoCSource.PASTEBIN
