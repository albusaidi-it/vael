"""
VAEL – Stage 4 / Internet Exposure Checker

Queries Shodan and Censys for internet-exposed hosts matching the affected
software/version, estimating real-world attack surface.

Shodan:  requires SHODAN_API_KEY  (free tier = 1 search credit/query)
Censys:  requires CENSYS_API_ID + CENSYS_API_SECRET (250 queries/month free)

Both are optional — the checker degrades gracefully and returns UNKNOWN
when keys are not configured.

Shodan search syntax:
  product:"Apache Log4j" version:"2.14.1"
  http.component:"Spring Framework" http.component.version:"5.3.17"

Censys search syntax (v2 hosts):
  services.software.product="Log4j" AND services.software.version="2.14.1"
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

import base64

import httpx

from schemas.stage2 import Stage2Result
from schemas.stage4 import Stage4Result, ExposureResult, ExposureLevel, HostSample
from core.config import settings
from core import cache as _cache

logger = logging.getLogger(__name__)

_TTL = 6 * 3600   # 6 hours — exposure data changes faster than CVE data

SHODAN_SEARCH  = "https://api.shodan.io/shodan/host/search"
SHODAN_COUNT   = "https://api.shodan.io/shodan/host/count"
CENSYS_HOSTS   = "https://search.censys.io/api/v2/hosts/search"
FOFA_SEARCH    = "https://fofa.info/api/v1/search/all"
ZOOMEYE_SEARCH = "https://api.zoomeye.ai/host/search"


# ── Query builders ─────────────────────────────────────────────────────────────

def _fofa_query(software: str, version: str, cpe: Optional[str] = None) -> str:
    """Build a FOFA search query (base64-encoded)."""
    if cpe:
        parts = cpe.split(":")
        if len(parts) > 5:
            q = f'product="{parts[4]}" && version="{parts[5]}"'
            return base64.b64encode(q.encode()).decode()
    q = f'product="{software}" && version="{version}"'
    return base64.b64encode(q.encode()).decode()


def _zoomeye_query(software: str, version: str, cpe: Optional[str] = None) -> str:
    """Build a ZoomEye search query."""
    if cpe:
        parts = cpe.split(":")
        if len(parts) > 5:
            return f'app:"{parts[4]}" ver:"{parts[5]}"'
    return f'app:"{software}" ver:"{version}"'


def _shodan_query(software: str, version: str, cpe: Optional[str] = None) -> str:
    """Build a Shodan search query for a software + version."""
    if cpe:
        # cpe:2.3:a:apache:log4j2:2.14.1 → product:"log4j" version:"2.14.1"
        parts = cpe.split(":")
        if len(parts) > 5:
            return f'product:"{parts[4]}" version:"{parts[5]}"'
    # Fall back to product name
    return f'product:"{software}" version:"{version}"'


def _censys_query(software: str, version: str) -> str:
    return (
        f'services.software.product="{software}" '
        f'AND services.software.version="{version}"'
    )


# ── Shodan ─────────────────────────────────────────────────────────────────────

def _query_shodan(
    software: str,
    version: str,
    cpe: Optional[str] = None,
) -> ExposureResult:
    key_val = settings.shodan_api_key
    result  = ExposureResult(product_query=software, source="shodan", queried_at=datetime.utcnow())

    if not key_val:
        result.errors.append("SHODAN_API_KEY not configured")
        return result

    cache_key = _cache.make_key("shodan", software, version)
    cached    = _cache.get(cache_key)
    if cached:
        try:
            return ExposureResult.model_validate(cached)
        except Exception:
            pass

    query = _shodan_query(software, version, cpe)
    try:
        with httpx.Client(timeout=15) as client:
            # Use /count first (free, no credits)
            resp = client.get(SHODAN_COUNT, params={"key": key_val, "query": query})
            if resp.status_code == 401:
                result.errors.append("Shodan: invalid API key")
                return result
            resp.raise_for_status()
            data  = resp.json()
            count = data.get("total", 0)
            result.shodan_count = count

            # Fetch up to 10 host samples (1 page = 1 credit)
            if count > 0:
                s_resp = client.get(
                    SHODAN_SEARCH,
                    params={"key": key_val, "query": query, "page": 1},
                )
                if s_resp.status_code == 200:
                    sdata = s_resp.json()
                    for match in sdata.get("matches", [])[:10]:
                        result.samples.append(HostSample(
                            ip=match.get("ip_str", ""),
                            port=match.get("port"),
                            country=match.get("location", {}).get("country_code"),
                            org=match.get("org"),
                        ))
                    # Country breakdown
                    for match in sdata.get("matches", []):
                        cc = match.get("location", {}).get("country_code", "?")
                        result.top_countries[cc] = result.top_countries.get(cc, 0) + 1

    except httpx.RequestError as e:
        result.errors.append(f"Shodan request error: {e}")
    except Exception as e:
        result.errors.append(f"Shodan error: {e}")

    result.compute_total()
    result.compute_level()
    _cache.set(cache_key, "shodan", result.model_dump(mode="json"), _TTL)
    return result


# ── Censys ─────────────────────────────────────────────────────────────────────

def _query_censys(software: str, version: str) -> ExposureResult:
    api_id     = settings.censys_api_id
    api_secret = settings.censys_api_secret
    result     = ExposureResult(product_query=software, source="censys", queried_at=datetime.utcnow())

    if not api_id or not api_secret:
        result.errors.append("CENSYS_API_ID / CENSYS_API_SECRET not configured")
        return result

    cache_key = _cache.make_key("censys", software, version)
    cached    = _cache.get(cache_key)
    if cached:
        try:
            return ExposureResult.model_validate(cached)
        except Exception:
            pass

    query = _censys_query(software, version)
    try:
        with httpx.Client(timeout=20, auth=(api_id, api_secret)) as client:
            resp = client.post(CENSYS_HOSTS, json={"q": query, "per_page": 10})
            if resp.status_code == 401:
                result.errors.append("Censys: invalid credentials")
                return result
            resp.raise_for_status()
            data  = resp.json()
            count = data.get("result", {}).get("total", 0)
            result.censys_count = count

            for hit in data.get("result", {}).get("hits", []):
                result.samples.append(HostSample(
                    ip=hit.get("ip", ""),
                    country=hit.get("location", {}).get("country_code"),
                ))

    except httpx.RequestError as e:
        result.errors.append(f"Censys request error: {e}")
    except Exception as e:
        result.errors.append(f"Censys error: {e}")

    result.compute_total()
    result.compute_level()
    _cache.set(cache_key, "censys", result.model_dump(mode="json"), _TTL)
    return result


# ── FOFA ───────────────────────────────────────────────────────────────────────

def _query_fofa(software: str, version: str, cpe: Optional[str] = None) -> ExposureResult:
    """
    Query FOFA (fofa.info) — strong coverage of Asian/Chinese infrastructure.
    Requires FOFA_API_KEY + FOFA_EMAIL in config.
    FOFA free tier: 10,000 results/month; no per-query credit cost for count.
    """
    api_key = settings.fofa_api_key
    email   = settings.fofa_email
    result  = ExposureResult(product_query=software, source="fofa", queried_at=datetime.utcnow())

    if not api_key or not email:
        result.errors.append("FOFA_API_KEY / FOFA_EMAIL not configured")
        return result

    cache_key = _cache.make_key("fofa", software, version)
    cached    = _cache.get(cache_key)
    if cached:
        try:
            return ExposureResult.model_validate(cached)
        except Exception:
            pass

    qbase64 = _fofa_query(software, version, cpe)
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                FOFA_SEARCH,
                params={
                    "email":   email,
                    "key":     api_key,
                    "qbase64": qbase64,
                    "size":    10,
                    "fields":  "ip,port,country_code,org",
                },
            )
            if resp.status_code == 401:
                result.errors.append("FOFA: invalid API key or email")
                return result
            if resp.status_code == 402:
                result.errors.append("FOFA: quota exceeded")
                return result
            resp.raise_for_status()
            data = resp.json()
            if data.get("error"):
                result.errors.append(f"FOFA error: {data.get('errmsg', 'unknown')}")
                return result

            count = data.get("size", 0)
            result.fofa_count = count

            for row in data.get("results", [])[:10]:
                if len(row) >= 1:
                    result.samples.append(HostSample(
                        ip=row[0],
                        port=int(row[1]) if len(row) > 1 and row[1] else None,
                        country=row[2] if len(row) > 2 else None,
                        org=row[3] if len(row) > 3 else None,
                    ))
                    if len(row) > 2 and row[2]:
                        cc = row[2]
                        result.top_countries[cc] = result.top_countries.get(cc, 0) + 1

    except httpx.RequestError as e:
        result.errors.append(f"FOFA request error: {e}")
    except Exception as e:
        result.errors.append(f"FOFA error: {e}")

    result.compute_total()
    result.compute_level()
    _cache.set(cache_key, "fofa", result.model_dump(mode="json"), _TTL)
    return result


# ── ZoomEye ─────────────────────────────────────────────────────────────────────

def _query_zoomeye(software: str, version: str, cpe: Optional[str] = None) -> ExposureResult:
    """
    Query ZoomEye (zoomeye.ai) — broad global coverage complementing Shodan.
    Requires ZOOMEYE_API_KEY in config.
    Authentication: API-KEY header (ZoomEye v2).
    """
    api_key = settings.zoomeye_api_key
    result  = ExposureResult(product_query=software, source="zoomeye", queried_at=datetime.utcnow())

    if not api_key:
        result.errors.append("ZOOMEYE_API_KEY not configured")
        return result

    cache_key = _cache.make_key("zoomeye", software, version)
    cached    = _cache.get(cache_key)
    if cached:
        try:
            return ExposureResult.model_validate(cached)
        except Exception:
            pass

    query = _zoomeye_query(software, version, cpe)
    try:
        with httpx.Client(timeout=15, headers={"API-KEY": api_key}) as client:
            resp = client.get(ZOOMEYE_SEARCH, params={"query": query, "page": 1})
            if resp.status_code == 401:
                result.errors.append("ZoomEye: invalid API key")
                return result
            if resp.status_code == 403:
                result.errors.append("ZoomEye: API key quota exceeded or plan restriction")
                return result
            resp.raise_for_status()
            data = resp.json()

            count = data.get("total", 0)
            result.zoomeye_count = count

            for match in data.get("matches", [])[:10]:
                ip      = match.get("ip", "")
                port    = (match.get("portinfo") or {}).get("port")
                geo     = match.get("geoinfo") or {}
                country = (geo.get("country") or {}).get("code")
                org     = geo.get("organization")
                result.samples.append(HostSample(ip=ip, port=port, country=country, org=org))
                if country:
                    result.top_countries[country] = result.top_countries.get(country, 0) + 1

    except httpx.RequestError as e:
        result.errors.append(f"ZoomEye request error: {e}")
    except Exception as e:
        result.errors.append(f"ZoomEye error: {e}")

    result.compute_total()
    result.compute_level()
    _cache.set(cache_key, "zoomeye", result.model_dump(mode="json"), _TTL)
    return result


# ── Orchestrator ───────────────────────────────────────────────────────────────

def check_exposure(
    software: str,
    version: str,
    cpe: Optional[str] = None,
    cve_id: Optional[str] = None,
) -> ExposureResult:
    """
    Run Shodan, Censys, FOFA, and ZoomEye in parallel and merge results.

    Sources have overlapping coverage so total_exposed = max(all counts)
    to avoid double-counting — each individual count is still reported.
    """
    merged = ExposureResult(
        cve_id=cve_id,
        cpe_query=cpe,
        product_query=software,
        queried_at=datetime.utcnow(),
    )

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(_query_shodan,  software, version, cpe): "shodan",
            pool.submit(_query_censys,  software, version):      "censys",
            pool.submit(_query_fofa,    software, version, cpe): "fofa",
            pool.submit(_query_zoomeye, software, version, cpe): "zoomeye",
        }
        sources: list[str] = []
        seen_ips: set[str] = set()

        for fut in as_completed(futures):
            name   = futures[fut]
            result = fut.result()
            merged.errors.extend(result.errors)

            if result.shodan_count is not None:
                merged.shodan_count = result.shodan_count
                sources.append("Shodan")
            if result.censys_count is not None:
                merged.censys_count = result.censys_count
                sources.append("Censys")
            if result.fofa_count is not None:
                merged.fofa_count = result.fofa_count
                sources.append("FOFA")
            if result.zoomeye_count is not None:
                merged.zoomeye_count = result.zoomeye_count
                sources.append("ZoomEye")

            # Merge deduped host samples and country breakdown
            for s in result.samples:
                if s.ip not in seen_ips:
                    seen_ips.add(s.ip)
                    merged.samples.append(s)
            for cc, n in result.top_countries.items():
                merged.top_countries[cc] = merged.top_countries.get(cc, 0) + n

    merged.source = "+".join(sorted(set(sources))) if sources else ""
    merged.compute_total()   # max() across sources — avoids double-counting
    merged.compute_level()
    return merged


def run_stage4(
    stage2: Stage2Result,
    top_n: int = 5,
    cpe: Optional[str] = None,
) -> Stage4Result:
    """
    Run internet exposure check for the top-N priority CVEs.

    Shodan/Censys are queried ONCE for the (software, version) pair — the
    query is identical for every CVE since exposure is a property of the
    running software, not of any individual CVE. The result is then stamped
    onto each CVE's ExposureResult for UI consistency.
    """
    logger.info("Stage 4 starting for %s %s", stage2.software, stage2.version)

    result = Stage4Result(software=stage2.software, version=stage2.version)
    top    = stage2.top_priority_cves(limit=top_n)

    if not top:
        logger.info("No CVEs to check exposure for")
        return result

    # One query for (software, version) — not per-CVE
    base_exposure = check_exposure(
        software=stage2.software,
        version=stage2.version,
        cpe=cpe,
    )

    sources: set[str] = set()
    for cve, _enrichment in top:
        exposure = base_exposure.model_copy(update={"cve_id": cve.cve_id})
        result.exposures.append(exposure)
    if base_exposure.source:
        for s in base_exposure.source.split("+"):
            sources.add(s)

    result.sources_queried = sorted(sources)
    result.compute_summary()

    logger.info(
        "Stage 4 complete: %d total exposed hosts, peak level=%s",
        result.total_exposed, result.peak_level.value,
    )
    return result
