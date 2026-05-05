"""
Tests for core/http_client.py — shared persistent httpx singletons.
Verifies that the module exports the expected clients with the right configuration.
All tests are offline (no network calls made).
"""
from __future__ import annotations

import httpx
import pytest
from core import http_client


def test_api_client_is_httpx_client():
    assert isinstance(http_client.api, httpx.Client)


def test_scrape_client_is_httpx_client():
    assert isinstance(http_client.scrape, httpx.Client)


def test_scrape_noverify_client_is_httpx_client():
    assert isinstance(http_client.scrape_noverify, httpx.Client)


def test_all_three_are_distinct_instances():
    assert http_client.api is not http_client.scrape
    assert http_client.api is not http_client.scrape_noverify
    assert http_client.scrape is not http_client.scrape_noverify


def test_scrape_client_has_browser_user_agent():
    ua = http_client.scrape.headers.get("user-agent", "")
    assert "Mozilla" in ua


def test_scrape_noverify_ssl_disabled():
    assert http_client.scrape_noverify._transport is not None


def test_api_client_follows_redirects():
    assert http_client.api.follow_redirects is True


def test_scrape_client_follows_redirects():
    assert http_client.scrape.follow_redirects is True
