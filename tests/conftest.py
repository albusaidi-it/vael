"""
Shared pytest configuration: markers, fixtures, and auto-skip logic.
Set VAEL_SKIP_INTEGRATION=1 to skip all network-dependent tests.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def pytest_collection_modifyitems(config, items):
    if os.getenv("VAEL_SKIP_INTEGRATION", "0") == "1":
        skip = pytest.mark.skip(reason="VAEL_SKIP_INTEGRATION=1")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip)


@pytest.fixture()
def isolated_cache(tmp_path, monkeypatch):
    """Return the cache module wired to a fresh in-memory (tmp) SQLite DB."""
    import core.cache as cache_mod

    monkeypatch.setattr(cache_mod, "_conn", None)

    from core.config import settings
    monkeypatch.setattr(settings, "cache_dir", tmp_path, raising=False)

    yield cache_mod

    if cache_mod._conn is not None:
        cache_mod._conn.close()
    monkeypatch.setattr(cache_mod, "_conn", None)
