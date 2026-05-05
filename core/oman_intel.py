"""
VAEL – Oman Internet Exposure Intelligence
Searches Shodan, FOFA, and Censys for internet-exposed hosts in Oman
matching the target software or specific CVE IDs.

Country code: OM (Oman)
Sources:
  Shodan  — requires SHODAN_API_KEY
  FOFA    — requires FOFA_API_KEY + FOFA_EMAIL  (fofa.info)
  Censys  — requires CENSYS_API_ID + CENSYS_API_SECRET

All sources are optional and degrade gracefully if keys are missing.
"""

from __future__ import annotations

import base64
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional

import httpx
from core import http_client

from core import cache as _cache_mod
from core.config import settings
from core.rate_limiter import rate_limiter
from schemas.oman_intel import (
    OmanCVEHits,
    OmanHost,
    OmanIntelReport,
    OmanSourceResult,
)

logger = logging.getLogger(__name__)

_COUNTRY   = "OM"
_CACHE_TTL = 6 * 3600     # 6 hours — exposure data changes daily
_TIMEOUT   = 15            # seconds per HTTP call

# ── Shodan ────────────────────────────────────────────────────────────────────

def _shodan_query(software: str, version: str = "", cve_id: Optional[str] = None) -> str:
    if cve_id:
        # vuln: filter requires paid Shodan plan; CVE keyword search works on free tier
        return f'"{cve_id}" country:{_COUNTRY}'
    # product: searches Shodan's structured CPE product field (no version — Shodan
    # product names like "Apache httpd" don't always match user-provided short aliases)
    return f'product:"{software}" country:{_COUNTRY}'


def _search_shodan(software: str, version: str = "", cve_id: Optional[str] = None) -> OmanSourceResult:
    api_key = settings.shodan_api_key
    query   = _shodan_query(software, version, cve_id)

    if not api_key:
        return OmanSourceResult(source="Shodan", query_used=query,
                                error="SHODAN_API_KEY not configured")

    cache_key = _cache_mod.make_key("oman_shodan", query)
    if hit := _cache_mod.get(cache_key):
        logger.debug("Shodan cache hit for query: %s", query)
        return OmanSourceResult(**hit)

    dbg: dict = {"query": query}
    logger.info("[Shodan] querying: %s", query)

    try:
        client = http_client.api
        # ── /count (free tier, no credit cost) ───────────────────────────
        cr = client.get(
            "https://api.shodan.io/shodan/host/count",
            params={"key": api_key, "query": query},
            timeout=_TIMEOUT,
        )
        rate_limiter.record("shodan", dict(cr.headers), cr.status_code)
        dbg["count_status"] = cr.status_code
        logger.info("[Shodan] /count → HTTP %d", cr.status_code)

        if cr.status_code == 401:
            logger.warning("[Shodan] 401 Unauthorized — key invalid or expired")
            return OmanSourceResult(source="Shodan", query_used=query,
                                    error="Invalid SHODAN_API_KEY (HTTP 401)",
                                    debug_info=dbg)
        if cr.status_code == 403:
            logger.warning("[Shodan] 403 Forbidden — key lacks permissions")
            return OmanSourceResult(source="Shodan", query_used=query,
                                    error="SHODAN_API_KEY lacks permissions (HTTP 403)",
                                    debug_info=dbg)
        if cr.status_code != 200:
            body = cr.text[:300]
            logger.warning("[Shodan] /count unexpected status %d: %s", cr.status_code, body)
            dbg["count_body"] = body
            return OmanSourceResult(source="Shodan", query_used=query,
                                    error=f"Shodan /count returned HTTP {cr.status_code}",
                                    debug_info=dbg)

        count_data = cr.json()
        total = count_data.get("total", 0)
        dbg["count_total"] = total
        logger.info("[Shodan] /count total=%d for query: %s", total, query)

        if total == 0:
            if cve_id:
                dbg["hint"] = (
                    "0 CVE hits via keyword search — CVE IDs rarely appear in banners. "
                    "Shodan's vuln: filter (paid plan) gives more accurate CVE exposure data."
                )
            else:
                dbg["hint"] = (
                    "0 results — try a different product name variation "
                    "(e.g. 'Apache httpd', 'nginx', 'openssh') or verify on shodan.io"
                )
            logger.info("[Shodan] 0 results. hint: %s", dbg["hint"])

        hosts: list[OmanHost] = []
        if total > 0:
            # ── /search (1 credit per call on free tier) ─────────────────
            sr = client.get(
                "https://api.shodan.io/shodan/host/search",
                params={"key": api_key, "query": query, "minify": "true"},
                timeout=_TIMEOUT,
            )
            rate_limiter.record("shodan", dict(sr.headers), sr.status_code)
            dbg["search_status"] = sr.status_code
            logger.info("[Shodan] /search → HTTP %d", sr.status_code)

            if sr.status_code == 402:
                dbg["search_error"] = "HTTP 402 — /search requires a paid Shodan plan"
                logger.warning("[Shodan] /search requires paid plan (HTTP 402) — count only")
            elif sr.status_code == 200:
                matches = sr.json().get("matches", [])
                dbg["search_returned"] = len(matches)
                logger.info("[Shodan] /search returned %d matches", len(matches))
                for m in matches[:50]:
                    hosts.append(OmanHost(
                        ip=m.get("ip_str", ""),
                        port=m.get("port", 0),
                        protocol=m.get("transport", "tcp"),
                        city=m.get("location", {}).get("city"),
                        organization=m.get("org"),
                        banner=(m.get("data") or "")[:200],
                        source="shodan",
                    ))
            else:
                body = sr.text[:300]
                dbg["search_error"] = f"HTTP {sr.status_code}: {body}"
                logger.warning("[Shodan] /search failed HTTP %d: %s", sr.status_code, body)

        result = OmanSourceResult(
            source="Shodan", total_found=total,
            hosts=hosts, query_used=query, debug_info=dbg,
        )
        _cache_mod.set(cache_key, "oman_shodan", result.model_dump(mode="json"), _CACHE_TTL)
        return result

    except Exception as exc:
        dbg["exception"] = str(exc)
        logger.warning("[Shodan] query failed: %s", exc, exc_info=True)
        return OmanSourceResult(source="Shodan", query_used=query,
                                error=str(exc), debug_info=dbg)


# ── FOFA ─────────────────────────────────────────────────────────────────────

_FOFA_FIELDS = "ip,port,city,banner,protocol,title,org"
_FOFA_FIELD_IDX = {f: i for i, f in enumerate(_FOFA_FIELDS.split(","))}


def _fofa_query(software: str, version: str = "", cve_id: Optional[str] = None) -> str:
    if cve_id:
        return f'"{cve_id}" && country="OM"'
    # FOFA app= searches by category/product label; broader and more reliable than version match
    return f'app="{software}" && country="OM"'


def _search_fofa(software: str, version: str = "", cve_id: Optional[str] = None) -> OmanSourceResult:
    api_key = settings.fofa_api_key
    email   = settings.fofa_email
    query   = _fofa_query(software, version, cve_id)

    if not api_key or not email:
        return OmanSourceResult(source="FOFA", query_used=query,
                                error="FOFA_API_KEY / FOFA_EMAIL not configured")

    cache_key = _cache_mod.make_key("oman_fofa", query)
    if hit := _cache_mod.get(cache_key):
        logger.debug("FOFA cache hit for query: %s", query)
        return OmanSourceResult(**hit)

    dbg: dict = {"query": query}
    logger.info("[FOFA] querying: %s", query)

    try:
        qb64 = base64.b64encode(query.encode()).decode()
        resp = httpx.get(
            "https://fofa.info/api/v1/search/all",
            params={
                "email":   email,
                "key":     api_key,
                "qbase64": qb64,
                "fields":  _FOFA_FIELDS,
                "size":    100,
                "full":    "false",
            },
            timeout=_TIMEOUT,
        )
        rate_limiter.record("fofa", dict(resp.headers), resp.status_code)
        dbg["http_status"] = resp.status_code
        logger.info("[FOFA] → HTTP %d", resp.status_code)

        if resp.status_code != 200:
            body = resp.text[:300]
            dbg["response_body"] = body
            logger.warning("[FOFA] HTTP %d: %s", resp.status_code, body)
            return OmanSourceResult(source="FOFA", query_used=query,
                                    error=f"FOFA returned HTTP {resp.status_code}",
                                    debug_info=dbg)

        data = resp.json()
        dbg["api_error"] = data.get("error")
        dbg["errmsg"] = data.get("errmsg")

        if data.get("error"):
            errmsg = data.get("errmsg", "FOFA API error")
            logger.warning("[FOFA] API error: %s", errmsg)
            return OmanSourceResult(source="FOFA", query_used=query,
                                    error=errmsg, debug_info=dbg)

        total = data.get("size", 0)
        dbg["total_reported"] = total
        logger.info("[FOFA] total=%d for query: %s", total, query)

        hosts: list[OmanHost] = []
        for row in data.get("results", [])[:50]:
            def _f(name: str) -> str:
                idx = _FOFA_FIELD_IDX.get(name, -1)
                return (row[idx] if 0 <= idx < len(row) else None) or ""

            hosts.append(OmanHost(
                ip=_f("ip"),
                port=int(_f("port") or 0),
                protocol=(_f("protocol") or "tcp").lower(),
                city=_f("city") or None,
                organization=_f("org") or None,
                banner=(_f("banner") or _f("title") or "")[:200],
                source="fofa",
            ))

        dbg["hosts_parsed"] = len(hosts)
        result = OmanSourceResult(
            source="FOFA", total_found=total,
            hosts=hosts, query_used=query, debug_info=dbg,
        )
        _cache_mod.set(cache_key, "oman_fofa", result.model_dump(mode="json"), _CACHE_TTL)
        return result

    except Exception as exc:
        dbg["exception"] = str(exc)
        logger.warning("[FOFA] query failed: %s", exc, exc_info=True)
        return OmanSourceResult(source="FOFA", query_used=query,
                                error=str(exc), debug_info=dbg)


# ── Censys ────────────────────────────────────────────────────────────────────

def _censys_query(software: str, version: str = "", cve_id: Optional[str] = None) -> str:
    if cve_id:
        return (
            f'services.software.vulnerabilities.id: "{cve_id}" '
            f'and location.country_code: {_COUNTRY}'
        )
    return (
        f'services.software.product: "{software}" '
        f'and location.country_code: {_COUNTRY}'
    )


def _search_censys(software: str, version: str = "", cve_id: Optional[str] = None) -> OmanSourceResult:
    api_id  = settings.censys_api_id
    api_sec = settings.censys_api_secret
    query   = _censys_query(software, version, cve_id)

    if not api_id or not api_sec:
        return OmanSourceResult(source="Censys", query_used=query,
                                error="CENSYS_API_ID / CENSYS_API_SECRET not configured")

    cache_key = _cache_mod.make_key("oman_censys", query)
    if hit := _cache_mod.get(cache_key):
        logger.debug("Censys cache hit for query: %s", query)
        return OmanSourceResult(**hit)

    dbg: dict = {"query": query}
    logger.info("[Censys] querying: %s", query)

    try:
        resp = httpx.post(
            "https://search.censys.io/api/v2/hosts/search",
            json={"q": query, "per_page": 50},
            auth=(api_id, api_sec),
            timeout=_TIMEOUT,
        )
        rate_limiter.record("censys", dict(resp.headers), resp.status_code)
        dbg["http_status"] = resp.status_code
        logger.info("[Censys] → HTTP %d", resp.status_code)

        if resp.status_code in (401, 403):
            body = resp.text[:300]
            dbg["response_body"] = body
            logger.warning("[Censys] auth error %d: %s", resp.status_code, body)
            return OmanSourceResult(source="Censys", query_used=query,
                                    error=f"Invalid Censys credentials (HTTP {resp.status_code})",
                                    debug_info=dbg)
        if resp.status_code == 422:
            body = resp.text[:300]
            dbg["response_body"] = body
            logger.warning("[Censys] 422 invalid query: %s", body)
            return OmanSourceResult(source="Censys", query_used=query,
                                    error=f"Censys rejected query (HTTP 422): {body[:120]}",
                                    debug_info=dbg)
        if resp.status_code != 200:
            body = resp.text[:300]
            dbg["response_body"] = body
            logger.warning("[Censys] HTTP %d: %s", resp.status_code, body)
            return OmanSourceResult(source="Censys", query_used=query,
                                    error=f"Censys returned HTTP {resp.status_code}",
                                    debug_info=dbg)

        data = resp.json()
        result_data = data.get("result", {})
        total = result_data.get("total", 0)
        dbg["total_reported"] = total
        logger.info("[Censys] total=%d for query: %s", total, query)

        hosts: list[OmanHost] = []
        for h in result_data.get("hits", [])[:50]:
            services = h.get("services") or [{}]
            svc      = services[0]
            hosts.append(OmanHost(
                ip=h.get("ip", ""),
                port=svc.get("port", 0),
                protocol=(svc.get("transport_protocol") or "tcp").lower(),
                city=h.get("location", {}).get("city"),
                organization=h.get("autonomous_system", {}).get("name"),
                banner=(svc.get("banner") or "")[:200],
                source="censys",
            ))

        dbg["hosts_parsed"] = len(hosts)
        result = OmanSourceResult(
            source="Censys", total_found=total,
            hosts=hosts, query_used=query, debug_info=dbg,
        )
        _cache_mod.set(cache_key, "oman_censys", result.model_dump(mode="json"), _CACHE_TTL)
        return result

    except Exception as exc:
        dbg["exception"] = str(exc)
        logger.warning("[Censys] query failed: %s", exc, exc_info=True)
        return OmanSourceResult(source="Censys", query_used=query,
                                error=str(exc), debug_info=dbg)


# ── ZoomEye ───────────────────────────────────────────────────────────────────

_ZOOMEYE_API = "https://api.zoomeye.ai/host/search"


def _zoomeye_query(software: str, version: str = "", cve_id: Optional[str] = None) -> str:
    if cve_id:
        return f'"{cve_id}" country:"Oman"'
    return f'app:"{software}" country:"Oman"'


def _search_zoomeye(software: str, version: str = "", cve_id: Optional[str] = None) -> OmanSourceResult:
    api_key = settings.zoomeye_api_key
    query   = _zoomeye_query(software, version, cve_id)

    if not api_key:
        return OmanSourceResult(source="ZoomEye", query_used=query,
                                error="ZOOMEYE_API_KEY not configured")

    cache_key = _cache_mod.make_key("oman_zoomeye", query)
    if hit := _cache_mod.get(cache_key):
        logger.debug("ZoomEye cache hit for query: %s", query)
        return OmanSourceResult(**hit)

    dbg: dict = {"query": query}
    logger.info("[ZoomEye] querying: %s", query)

    try:
        resp = httpx.get(
            _ZOOMEYE_API,
            params={"query": query, "page": 1, "pagesize": 50},
            headers={"Authorization": f"JWT {api_key}"},
            timeout=_TIMEOUT,
        )
        rate_limiter.record("zoomeye", dict(resp.headers), resp.status_code)
        dbg["http_status"] = resp.status_code
        logger.info("[ZoomEye] → HTTP %d", resp.status_code)

        if resp.status_code == 401:
            logger.warning("[ZoomEye] 401 Unauthorized — invalid or expired key")
            return OmanSourceResult(source="ZoomEye", query_used=query,
                                    error="Invalid ZOOMEYE_API_KEY (HTTP 401)",
                                    debug_info=dbg)
        if resp.status_code == 403:
            body = resp.text[:300]
            dbg["response_body"] = body
            logger.warning("[ZoomEye] 403: %s", body)
            return OmanSourceResult(source="ZoomEye", query_used=query,
                                    error=f"ZoomEye access denied (HTTP 403): {body[:120]}",
                                    debug_info=dbg)
        if resp.status_code != 200:
            body = resp.text[:300]
            dbg["response_body"] = body
            logger.warning("[ZoomEye] HTTP %d: %s", resp.status_code, body)
            return OmanSourceResult(source="ZoomEye", query_used=query,
                                    error=f"ZoomEye returned HTTP {resp.status_code}",
                                    debug_info=dbg)

        data  = resp.json()
        total = data.get("total", 0)
        dbg["total_reported"] = total
        logger.info("[ZoomEye] total=%d for query: %s", total, query)

        hosts: list[OmanHost] = []
        for m in data.get("matches", [])[:50]:
            portinfo = m.get("portinfo") or {}
            geoinfo  = m.get("geoinfo")  or {}
            city_obj = geoinfo.get("city") or {}
            city     = (city_obj.get("names") or {}).get("en") or None
            org      = geoinfo.get("organization") or None
            hosts.append(OmanHost(
                ip=m.get("ip", ""),
                port=portinfo.get("port", 0),
                protocol=(portinfo.get("transport") or "tcp").lower(),
                city=city,
                organization=org,
                banner=(portinfo.get("banner") or "")[:200],
                source="zoomeye",
            ))

        dbg["hosts_parsed"] = len(hosts)
        result = OmanSourceResult(
            source="ZoomEye", total_found=total,
            hosts=hosts, query_used=query, debug_info=dbg,
        )
        _cache_mod.set(cache_key, "oman_zoomeye", result.model_dump(mode="json"), _CACHE_TTL)
        return result

    except Exception as exc:
        dbg["exception"] = str(exc)
        logger.warning("[ZoomEye] query failed: %s", exc, exc_info=True)
        return OmanSourceResult(source="ZoomEye", query_used=query,
                                error=str(exc), debug_info=dbg)


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_oman_intel(
    software:   str,
    version:    str,
    cve_ids:    Optional[list[str]] = None,
    cve_source: str = "none",
) -> OmanIntelReport:
    """
    Query Shodan, FOFA, Censys, and ZoomEye for internet-exposed hosts in Oman.

    CVE-targeted searches (vuln:/app CVE filter) are the primary signal —
    they look for hosts with a known vulnerability, not just any host running
    the software. Software-name searches (product: filter) run in parallel as
    a secondary fallback.

    Returns an OmanIntelReport with aggregated counts and sample host data.
    """
    # ── Software+version searches (finds hosts running the product in Oman) ─────
    sw_tasks: dict[str, tuple] = {
        "shodan":  (_search_shodan,  software, version, None),
        "fofa":    (_search_fofa,    software, version, None),
        "censys":  (_search_censys,  software, version, None),
        "zoomeye": (_search_zoomeye, software, version, None),
    }

    # ── CVE-targeted searches (top 5 CVEs × 4 sources) ────────────────────────
    cve_tasks: dict[str, tuple] = {}
    target_cves = (cve_ids or [])[:5]
    for cve_id in target_cves:
        cve_tasks[f"shodan_{cve_id}"]  = (_search_shodan,  software, version, cve_id)
        cve_tasks[f"fofa_{cve_id}"]    = (_search_fofa,    software, version, cve_id)
        cve_tasks[f"censys_{cve_id}"]  = (_search_censys,  software, version, cve_id)
        cve_tasks[f"zoomeye_{cve_id}"] = (_search_zoomeye, software, version, cve_id)

    all_tasks = {**sw_tasks, **cve_tasks}

    sw_results:  list[OmanSourceResult] = []
    cve_buckets: dict[str, dict[str, int]] = {c: {} for c in target_cves}

    with ThreadPoolExecutor(max_workers=min(len(all_tasks), 12)) as pool:
        futures = {
            pool.submit(fn, sw, ver, cve): key
            for key, (fn, sw, ver, cve) in all_tasks.items()
        }
        for fut, key in futures.items():
            try:
                result: OmanSourceResult = fut.result(timeout=25)
            except Exception as exc:
                logger.warning("Oman intel task %s failed: %s", key, exc)
                continue

            if key in sw_tasks:
                sw_results.append(result)
            else:
                # key = "shodan_CVE-XXXX" — parse out CVE and source
                parts = key.split("_", 1)
                src_name = parts[0]
                cve_id_  = parts[1] if len(parts) > 1 else ""
                if cve_id_ in cve_buckets:
                    cve_buckets[cve_id_][src_name] = result.total_found

    # ── Aggregate host data from software-level results ───────────────────────
    all_hosts: list[OmanHost] = [h for sr in sw_results for h in sr.hosts]

    seen_ips: set[str] = set()
    unique_hosts: list[OmanHost] = []
    for h in all_hosts:
        if h.ip not in seen_ips:
            seen_ips.add(h.ip)
            unique_hosts.append(h)

    city_counts: dict[str, int] = {}
    port_counts: dict[str, int] = {}
    for h in unique_hosts:
        if h.city:
            city_counts[h.city] = city_counts.get(h.city, 0) + 1
        port_counts[str(h.port)] = port_counts.get(str(h.port), 0) + 1

    sources_queried = [sr.source for sr in sw_results if not sr.error]
    total_exposed   = sum(sr.total_found for sr in sw_results)
    by_source       = {sr.source: sr.total_found for sr in sw_results}

    # ── CVE hit summaries ─────────────────────────────────────────────────────
    cve_hits: list[OmanCVEHits] = []
    for cve_id in target_cves:
        bucket = cve_buckets.get(cve_id, {})
        sh = bucket.get("shodan",  0)
        fo = bucket.get("fofa",    0)
        ce = bucket.get("censys",  0)
        ze = bucket.get("zoomeye", 0)
        cve_hits.append(OmanCVEHits(
            cve_id=cve_id,
            shodan_count=sh,
            fofa_count=fo,
            censys_count=ce,
            zoomeye_count=ze,
            total=sh + fo + ce + ze,
        ))

    # ── Rate limit warnings ───────────────────────────────────────────────────
    rl_warnings = rate_limiter.collect_warnings(
        ["shodan", "fofa", "censys", "zoomeye"],
        {"shodan":   bool(settings.shodan_api_key),
         "fofa":     bool(settings.fofa_api_key),
         "censys":   bool(settings.censys_api_id),
         "zoomeye":  bool(settings.zoomeye_api_key)},
    )

    return OmanIntelReport(
        software=software,
        version=version,
        total_exposed=total_exposed,
        unique_ips_sampled=len(unique_hosts),
        hosts_by_city=dict(sorted(city_counts.items(), key=lambda x: -x[1])[:10]),
        hosts_by_port=dict(sorted(port_counts.items(), key=lambda x: -x[1])[:10]),
        hosts_by_source=by_source,
        sources_queried=sources_queried,
        source_results=sw_results,
        cve_hits=cve_hits,
        cve_ids_searched=target_cves,
        cve_source=cve_source,
        rate_limit_warnings=rl_warnings,
        queried_at=datetime.now(timezone.utc).isoformat(),
    )
