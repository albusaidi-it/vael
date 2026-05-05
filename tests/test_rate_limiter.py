"""
Tests for core/rate_limiter.py — per-API budget tracker.
All tests are offline; they operate on a fresh RateLimiter instance
to avoid polluting the module-level singleton.
"""
from __future__ import annotations

import pytest
from core.rate_limiter import RateLimitTracker


@pytest.fixture()
def limiter():
    """Fresh RateLimitTracker instance per test."""
    return RateLimitTracker()


def test_status_contains_all_known_apis(limiter):
    status = limiter.status()
    for api in ("github", "nvd", "osv", "shodan", "vulncheck", "attackerkb", "pastebin"):
        assert api in status, f"Expected '{api}' in rate limiter status"


def test_record_429_marks_exhausted(limiter):
    limiter.record("github", {}, 429)
    status = limiter.status()
    assert status["github"]["throttle_events"] >= 1


def test_record_403_marks_exhausted(limiter):
    limiter.record("nvd", {}, 403)
    status = limiter.status()
    assert status["nvd"]["throttle_events"] >= 1


def test_github_header_parsing(limiter):
    # httpx lowercases headers when converting to dict, so mirror that here
    headers = {
        "x-ratelimit-remaining": "10",
        "x-ratelimit-limit": "5000",
    }
    limiter.record("github", headers, 200)
    status = limiter.status()
    assert status["github"]["remaining"] == 10


def test_warn_and_log_returns_none_when_healthy(limiter):
    warn = limiter.warn_and_log("github", has_key=True)
    assert warn is None


def test_warn_and_log_returns_message_when_exhausted(limiter):
    limiter.record("github", {}, 429)
    warn = limiter.warn_and_log("github", has_key=False)
    assert warn is not None
    assert isinstance(warn, str)


def test_session_usage_increments(limiter):
    initial = limiter.status().get("github", {}).get("used_this_session", 0)
    limiter.record("github", {}, 200)
    after = limiter.status().get("github", {}).get("used_this_session", 0)
    assert after == initial + 1


def test_unknown_api_does_not_raise(limiter):
    limiter.record("completely_unknown_api", {}, 200)
    limiter.warn_and_log("completely_unknown_api", has_key=False)
