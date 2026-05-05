"""
VAEL – SQLite cache layer.

Two distinct concerns live here:

1. API response cache  (get / set / delete / purge / stats)
   Short-lived, keyed by sha256 of query params, zlib-compressed.
   Schema: cache(key, source, data, compressed, created_at, expires_at)

2. Bulk feed storage  (epss / kev / exploitdb tables)
   Long-lived, refreshed on a TTL schedule, queried by CVE ID.
   Schema: feeds_meta + epss + kev + exploitdb
   No file-based CSV/JSON — everything lives in vael_cache.db.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import threading
import time
from typing import Any, Optional

from core.config import settings

logger = logging.getLogger(__name__)

_COMPRESS_THRESHOLD = 4096   # bytes

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key        TEXT PRIMARY KEY,
    source     TEXT NOT NULL,
    data       BLOB NOT NULL,
    compressed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_source  ON cache(source);

-- Feed metadata: tracks last refresh time and per-feed extras (e.g. score_date).
CREATE TABLE IF NOT EXISTS feeds_meta (
    feed_name    TEXT PRIMARY KEY,
    last_updated INTEGER NOT NULL DEFAULT 0,
    row_count    INTEGER NOT NULL DEFAULT 0,
    meta         TEXT DEFAULT '{}'
);

-- EPSS daily scores (~200 k rows, keyed by CVE ID).
CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    epss       REAL NOT NULL,
    percentile REAL NOT NULL,
    score_date TEXT
);

-- CISA KEV catalog (~1 k rows).
CREATE TABLE IF NOT EXISTS kev (
    cve_id                        TEXT PRIMARY KEY,
    vendor_project                TEXT,
    product                       TEXT,
    vulnerability_name            TEXT,
    date_added                    TEXT,
    short_description             TEXT,
    required_action               TEXT,
    due_date                      TEXT,
    known_ransomware_campaign_use TEXT,
    notes                         TEXT
);

-- Exploit-DB catalog (~50 k rows, one row per CVE per exploit entry).
CREATE TABLE IF NOT EXISTS exploitdb (
    row_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    edb_id         TEXT NOT NULL,
    cve_id         TEXT NOT NULL,
    description    TEXT,
    date_published TEXT,
    author         TEXT,
    type           TEXT,
    platform       TEXT,
    file           TEXT,
    codes          TEXT
);
CREATE INDEX IF NOT EXISTS idx_exploitdb_cve ON exploitdb(cve_id);
"""

_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is not None:
        return _conn
    with _lock:
        if _conn is not None:
            return _conn
        db_path = settings.cache_db_path()
        conn = sqlite3.connect(str(db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(_SCHEMA)
        conn.commit()
        _conn = conn
        logger.debug("SQLite cache opened: %s", db_path)
    return _conn


# ── API response cache ────────────────────────────────────────────────────────

# TTL for the full assembled pipeline result (stage1+stage2+stage3+verdict).
# Shorter than individual source TTLs so refreshes happen when any source changes.
_PIPELINE_TTL = 4 * 3600   # 4 hours


def make_key(source: str, *parts: str) -> str:
    """Deterministic cache key: sha256(source:part1:part2:...)[:24]"""
    raw = f"{source}:" + ":".join(str(p).lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def pipeline_cache_key(
    software: str,
    version: str,
    ecosystem: str = "",
    deterministic: bool = False,
    top_n: int = 10,
) -> str:
    """
    Stable key for a full pipeline run (stage1+stage2+stage3+verdict).

    Only the inputs that materially change the output are included:
      - software / version / ecosystem  → change which CVEs are found
      - deterministic                   → changes verdict engine (AI vs rule-based)
      - top_n                           → changes how many CVEs get PoC harvesting

    Intentionally excluded: offline, skip_nvd, skip_osv, skip_github (partial
    runs), github_token / gemini_api_key (credentials).
    """
    return make_key(
        "pipeline",
        software.lower().strip(),
        version.lower().strip(),
        (ecosystem or "").lower().strip(),
        str(deterministic),
        str(top_n),
    )


def get(key: str) -> Optional[Any]:
    """Return cached value (parsed JSON) or None if missing/expired."""
    import zlib
    try:
        conn = _get_conn()
        now  = int(time.time())
        row  = conn.execute(
            "SELECT data, compressed FROM cache WHERE key=? AND expires_at>?",
            (key, now),
        ).fetchone()
        if row is None:
            return None
        raw = bytes(row["data"])
        if row["compressed"]:
            raw = zlib.decompress(raw)
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        logger.debug("Cache get error (key=%s): %s", key, e)
        return None


def set(key: str, source: str, value: Any, ttl_seconds: int) -> None:
    """Store value in cache with TTL. value must be JSON-serialisable."""
    import zlib
    try:
        conn = _get_conn()
        now  = int(time.time())
        raw  = json.dumps(value, default=str).encode("utf-8")
        compressed = 0
        if len(raw) > _COMPRESS_THRESHOLD:
            raw = zlib.compress(raw, level=6)
            compressed = 1
        with _lock:
            conn.execute(
                "INSERT OR REPLACE INTO cache(key,source,data,compressed,created_at,expires_at) "
                "VALUES (?,?,?,?,?,?)",
                (key, source, raw, compressed, now, now + ttl_seconds),
            )
            conn.commit()
    except Exception as e:
        logger.debug("Cache set error (key=%s): %s", key, e)


def delete(key: str) -> None:
    try:
        conn = _get_conn()
        with _lock:
            conn.execute("DELETE FROM cache WHERE key=?", (key,))
            conn.commit()
    except Exception as e:
        logger.debug("Cache delete error: %s", e)


def purge_expired() -> int:
    """Delete all expired API cache entries. Returns count deleted."""
    try:
        conn = _get_conn()
        with _lock:
            cur = conn.execute("DELETE FROM cache WHERE expires_at<=?", (int(time.time()),))
            conn.commit()
            return cur.rowcount
    except Exception as e:
        logger.debug("Cache purge error: %s", e)
        return 0


def stats() -> dict:
    """Return cache statistics for API cache and bulk feed tables."""
    try:
        conn = _get_conn()
        now  = int(time.time())
        rows = conn.execute(
            "SELECT source, COUNT(*) as cnt, SUM(LENGTH(data)) as bytes "
            "FROM cache WHERE expires_at>? GROUP BY source",
            (now,),
        ).fetchall()
        feed_rows = conn.execute(
            "SELECT feed_name, row_count, last_updated FROM feeds_meta"
        ).fetchall()
        return {
            "entries_by_source": {
                r["source"]: {"count": r["cnt"], "bytes": r["bytes"]} for r in rows
            },
            "feeds": {
                r["feed_name"]: {
                    "row_count": r["row_count"],
                    "last_updated": r["last_updated"],
                }
                for r in feed_rows
            },
            "db_path": str(settings.cache_db_path()),
        }
    except Exception as e:
        return {"error": str(e)}


# ── Bulk feed helpers ─────────────────────────────────────────────────────────

def feed_is_stale(feed_name: str, ttl_seconds: int) -> bool:
    """True if the feed has never been loaded or its TTL has expired."""
    try:
        row = _get_conn().execute(
            "SELECT last_updated FROM feeds_meta WHERE feed_name=?", (feed_name,)
        ).fetchone()
        if row is None:
            return True
        return (int(time.time()) - row["last_updated"]) > ttl_seconds
    except Exception:
        return True


def feed_mark_updated(feed_name: str, row_count: int, meta: Optional[dict] = None) -> None:
    """Record a successful feed refresh."""
    try:
        with _lock:
            _get_conn().execute(
                "INSERT OR REPLACE INTO feeds_meta(feed_name, last_updated, row_count, meta) "
                "VALUES (?,?,?,?)",
                (feed_name, int(time.time()), row_count, json.dumps(meta or {})),
            )
            _get_conn().commit()
    except Exception as e:
        logger.debug("feed_mark_updated error: %s", e)


def feed_get_meta(feed_name: str) -> dict:
    """Return the stored metadata dict for a feed (empty dict if none)."""
    try:
        row = _get_conn().execute(
            "SELECT meta FROM feeds_meta WHERE feed_name=?", (feed_name,)
        ).fetchone()
        if row:
            return json.loads(row["meta"] or "{}")
    except Exception:
        pass
    return {}


# ── EPSS helpers ──────────────────────────────────────────────────────────────

def epss_upsert_batch(rows: list[tuple]) -> None:
    """
    Bulk-insert EPSS rows. Each row: (cve_id, epss, percentile, score_date).
    Uses a full table replace: DELETE then INSERT in one transaction for
    atomicity — readers never see a half-loaded table.
    """
    try:
        conn = _get_conn()
        with _lock:
            conn.execute("DELETE FROM epss")
            conn.executemany(
                "INSERT INTO epss(cve_id, epss, percentile, score_date) VALUES (?,?,?,?)",
                rows,
            )
            conn.commit()
    except Exception as e:
        logger.error("epss_upsert_batch failed: %s", e)


def epss_lookup_many(cve_ids: list[str]) -> dict[str, Optional[dict]]:
    """Return EPSS row dicts keyed by CVE ID (uppercase). Missing → None."""
    if not cve_ids:
        return {}
    upper = [c.upper() for c in cve_ids]
    try:
        placeholders = ",".join("?" * len(upper))
        rows = _get_conn().execute(
            f"SELECT cve_id, epss, percentile, score_date FROM epss WHERE cve_id IN ({placeholders})",
            upper,
        ).fetchall()
        found = {r["cve_id"]: dict(r) for r in rows}
        return {cid: found.get(cid) for cid in upper}
    except Exception as e:
        logger.debug("epss_lookup_many error: %s", e)
        return {cid: None for cid in upper}


# ── KEV helpers ───────────────────────────────────────────────────────────────

def kev_upsert_batch(rows: list[tuple]) -> None:
    """
    Bulk-insert KEV rows. Each row is a 10-tuple matching the kev table columns
    (cve_id, vendor_project, product, vulnerability_name, date_added,
     short_description, required_action, due_date,
     known_ransomware_campaign_use, notes).
    Full table replace for atomicity.
    """
    try:
        conn = _get_conn()
        with _lock:
            conn.execute("DELETE FROM kev")
            conn.executemany(
                "INSERT INTO kev VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
            conn.commit()
    except Exception as e:
        logger.error("kev_upsert_batch failed: %s", e)


def kev_lookup_many(cve_ids: list[str]) -> dict[str, Optional[dict]]:
    """Return KEV row dicts keyed by CVE ID. Missing → None."""
    if not cve_ids:
        return {}
    upper = [c.upper() for c in cve_ids]
    try:
        placeholders = ",".join("?" * len(upper))
        rows = _get_conn().execute(
            f"SELECT * FROM kev WHERE cve_id IN ({placeholders})", upper
        ).fetchall()
        found = {r["cve_id"]: dict(r) for r in rows}
        return {cid: found.get(cid) for cid in upper}
    except Exception as e:
        logger.debug("kev_lookup_many error: %s", e)
        return {cid: None for cid in upper}


# ── ExploitDB helpers ─────────────────────────────────────────────────────────

def exploitdb_load_batch(rows: list[tuple]) -> None:
    """
    Full replace of the exploitdb table. Each row is a 9-tuple:
    (edb_id, cve_id, description, date_published, author, type, platform, file, codes).
    """
    try:
        conn = _get_conn()
        with _lock:
            conn.execute("DELETE FROM exploitdb")
            conn.executemany(
                "INSERT INTO exploitdb"
                "(edb_id,cve_id,description,date_published,author,type,platform,file,codes)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                rows,
            )
            conn.commit()
    except Exception as e:
        logger.error("exploitdb_load_batch failed: %s", e)


def exploitdb_lookup(cve_id: str) -> list[dict]:
    """Return all ExploitDB rows for a CVE ID."""
    try:
        rows = _get_conn().execute(
            "SELECT * FROM exploitdb WHERE cve_id=?", (cve_id.upper(),)
        ).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        logger.debug("exploitdb_lookup error: %s", e)
        return []
