# Contributing

This page explains how to extend VAEL by adding new data sources, stages, or harvesters.

---

## Code Style

- Python 3.10+ type hints throughout
- Pydantic v2 for all data models
- `httpx` for HTTP requests (sync, not async — the pipeline uses `ThreadPoolExecutor`)
- `from __future__ import annotations` at the top of every file
- `from core import cache as _cache_mod` pattern for cache access — use module-level functions `_cache_mod.get(...)`, `_cache_mod.set(...)`, `_cache_mod.make_key(...)` (not `_cache_mod._cache.method()`)
- All external I/O is wrapped in try/except and degrades gracefully

---

## Adding a New PoC Source (Stage 3)

### 1. Create the harvester file

Create `core/yourplatform_harvester.py`. The minimal interface:

```python
from __future__ import annotations
from typing import Optional
from schemas.stage3 import PoCRecord, PoCQuality, PoCSource, VersionCompatibility
from core import cache as _cache_mod

CACHE_TTL = 86400  # seconds

def search_yourplatform(cve_id: str, software: str, version: str) -> list[PoCRecord]:
    cache_key = _cache_mod.make_key("yourplatform", cve_id)
    cached = _cache_mod.get(cache_key)
    if cached:
        return [PoCRecord(**r) for r in cached]

    results: list[PoCRecord] = []

    try:
        # ... fetch and parse ...
        pass
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("yourplatform failed for %s: %s", cve_id, exc)
        return []

    _cache_mod.set(cache_key, [r.model_dump(mode="json") for r in results], ttl=CACHE_TTL)
    return results
```

Key points:
- Always check the cache first and write results back to it
- Return an empty list on any error — never propagate exceptions
- Set `raw_meta={"discovered_via": "YourPlatform"}` if it's an international/search-engine source so the UI puts it in the international section

### 2. Add the source to `PoCSource` enum

In `schemas/stage3.py`, add your platform to the `PoCSource` enum:

```python
class PoCSource(str, Enum):
    GITHUB = "GITHUB"
    EXPLOITDB = "EXPLOITDB"
    # ... existing ...
    YOUR_PLATFORM = "YOUR_PLATFORM"
```

### 3. Wire it into `poc_harvester.py`

In `core/poc_harvester.py`:

```python
from core.yourplatform_harvester import search_yourplatform

def harvest_cve(cve_id, software, version, ..., skip_your_platform=False):
    futures = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        # ... existing submissions ...
        if not skip_your_platform:
            futures["your_platform"] = pool.submit(
                search_yourplatform, cve_id, software, version
            )

    pocs: list[PoCRecord] = []
    for key, fut in futures.items():
        try:
            pocs.extend(fut.result(timeout=20))
        except Exception as exc:
            logger.warning("%s harvester failed: %s", key, exc)

    return pocs
```

Also add `"your_platform"` to the `sources_queried` list in `run_stage3()`.

### 4. Add rate limit tracking

In `core/rate_limiter.py`, add an entry to `_API_CONFIG`:

```python
_API_CONFIG = {
    # ... existing ...
    "your_platform": APIBudget(
        limit=100,
        warning_threshold=0.2,
        display_name="YourPlatform",
    ),
}
```

### 5. Update the UI (if international)

If your source is a search engine or international platform, add it to the `INTL_ENGINES` constant in `web/index.html`:

```javascript
const INTL_ENGINES = {
    // ... existing ...
    'YourPlatform': { flag: '🌐', label: 'YourPlatform (Country)' },
};
```

---

## Adding a New CVE Source (Stage 1)

### 1. Create the fetcher file

Create `core/yourdb_fetcher.py`:

```python
from __future__ import annotations
from schemas.stage1 import CVERecord
from core import cache as _cache_mod

def fetch_yourdb(software: str, version: str, ...) -> list[CVERecord]:
    cache_key = _cache_mod.make_key("yourdb", software, version)
    cached = _cache_mod.get(cache_key)
    if cached:
        return [CVERecord(**r) for r in cached]

    results: list[CVERecord] = []
    # ... fetch and parse into CVERecord objects ...

    _cache_mod.set(cache_key, [r.model_dump(mode="json") for r in results], ttl=86400)
    return results
```

### 2. Wire into `cve_mapper.py`

In `core/cve_mapper.py`, add a concurrent submission inside `run_stage1()`:

```python
from core.yourdb_fetcher import fetch_yourdb

futures["yourdb"] = pool.submit(fetch_yourdb, software, version)
```

Then merge the results into the deduplication dict (`by_cve_id`).

---

## Adding a New Enrichment Source (Stage 2)

### 1. Create the fetcher

Create `core/yourenrich_fetcher.py` returning a dict mapping CVE IDs to your enrichment data.

### 2. Wire into `exploit_eval.py`

Add a concurrent submission in `run_stage2()` and merge into the `ExploitabilityEnrichment` objects.

### 3. Update the schema

If you're adding new fields to `ExploitabilityEnrichment`, update `schemas/stage2.py`.

---

## Schema Changes

All schemas are Pydantic v2 models in `schemas/`. When adding new fields:

- Make new fields `Optional[T] = None` to maintain backwards compatibility with cached data
- Update the corresponding wiki page in `wiki/`
- If changing Stage 3, ensure the `raw_meta` dict convention is preserved for the UI's international section

---

## Testing

Run existing tests with:

```bash
pytest tests/
```

For a new harvester, add a test in `tests/test_yourplatform.py`:

```python
def test_search_yourplatform_returns_list():
    results = search_yourplatform("CVE-2021-44228", "log4j", "2.14.1")
    assert isinstance(results, list)
    # Each result must be a valid PoCRecord
    for r in results:
        assert r.cve_id == "CVE-2021-44228"
        assert r.source is not None
        assert r.url is not None
```

Use the fixture data in `fixtures/` for offline tests.

---

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/add-vulndb-source`
3. Add your harvester, schema changes, and tests
4. Verify `pytest tests/` passes
5. Open a pull request with a description of the source, what it provides, and any rate limits or access restrictions
