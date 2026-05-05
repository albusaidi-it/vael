"""
Tests for core/cache.py — SQLite cache layer.
All tests are offline; they use the isolated_cache fixture to get a
fresh temp DB per test so there is no state leak between tests.
"""
from __future__ import annotations

import time


def test_make_key_deterministic():
    from core.cache import make_key
    assert make_key("nvd", "log4j", "2.14.1") == make_key("nvd", "log4j", "2.14.1")


def test_make_key_case_insensitive():
    from core.cache import make_key
    assert make_key("nvd", "LOG4J") == make_key("nvd", "log4j")


def test_make_key_length():
    from core.cache import make_key
    assert len(make_key("nvd", "log4j")) == 24


def test_make_key_different_sources_differ():
    from core.cache import make_key
    assert make_key("nvd", "log4j") != make_key("osv", "log4j")


def test_set_and_get_roundtrip(isolated_cache):
    cache = isolated_cache
    key = cache.make_key("test", "roundtrip")
    cache.set(key, "test", {"hello": "world", "n": 42}, ttl_seconds=60)
    result = cache.get(key)
    assert result == {"hello": "world", "n": 42}


def test_get_missing_returns_none(isolated_cache):
    cache = isolated_cache
    assert cache.get("nonexistent_key_xyz") is None


def test_get_expired_returns_none(isolated_cache):
    cache = isolated_cache
    key = cache.make_key("test", "ttl_zero")
    cache.set(key, "test", {"v": 1}, ttl_seconds=1)
    # Manually expire by patching expires_at to the past
    conn = cache._get_conn()
    conn.execute("UPDATE cache SET expires_at=? WHERE key=?", (int(time.time()) - 10, key))
    conn.commit()
    assert cache.get(key) is None


def test_set_overwrites_existing(isolated_cache):
    cache = isolated_cache
    key = cache.make_key("test", "overwrite")
    cache.set(key, "test", {"v": 1}, ttl_seconds=60)
    cache.set(key, "test", {"v": 2}, ttl_seconds=60)
    assert cache.get(key) == {"v": 2}


def test_large_value_compressed(isolated_cache):
    cache = isolated_cache
    key = cache.make_key("test", "large")
    big = {"data": "x" * 8000}
    cache.set(key, "test", big, ttl_seconds=60)
    conn = cache._get_conn()
    row = conn.execute("SELECT compressed FROM cache WHERE key=?", (key,)).fetchone()
    assert row["compressed"] == 1
    assert cache.get(key) == big


def test_purge_expired_removes_stale(isolated_cache):
    cache = isolated_cache
    k1 = cache.make_key("test", "keep")
    k2 = cache.make_key("test", "expire")
    cache.set(k1, "test", {"keep": True}, ttl_seconds=3600)
    cache.set(k2, "test", {"gone": True}, ttl_seconds=1)
    conn = cache._get_conn()
    conn.execute("UPDATE cache SET expires_at=? WHERE key=?", (int(time.time()) - 1, k2))
    conn.commit()
    deleted = cache.purge_expired()
    assert deleted >= 1
    assert cache.get(k1) is not None
    assert cache.get(k2) is None


def test_stats_returns_dict(isolated_cache):
    cache = isolated_cache
    cache.set(cache.make_key("nvd", "x"), "nvd", {"x": 1}, ttl_seconds=60)
    s = cache.stats()
    assert "entries_by_source" in s
    assert "nvd" in s["entries_by_source"]
