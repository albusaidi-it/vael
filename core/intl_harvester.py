"""
VAEL – International PoC Harvester

Searches non-English sources that English-only pipelines miss:

  Gitee  (gitee.com)     — Chinese GitHub alternative, REST API.
  Seebug (seebug.org)    — Curated Chinese CVE/PoC database.
  CNVD   (cnvd.org.cn)   — China National Vulnerability Database (official).
  Naver  (naver.com)     — Korean search engine, Korean security terms.
  Yandex (yandex.com)    — Russian search engine, Russian security terms.
                           Falls back to empty when CAPTCHA is triggered.
  Baidu  (baidu.com)     — Chinese search engine.
                           Falls back to empty (JS-rendered, no static links).

All results carry raw_meta["discovered_via"] so the dashboard can show
which engine/platform found each entry.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from typing import Optional

import httpx
from core import http_client
from bs4 import BeautifulSoup

from core import cache as _cache_mod
from core.rate_limiter import rate_limiter
from schemas.stage3 import PoCRecord, PoCSource, PoCQuality, VersionCompatibility

logger = logging.getLogger(__name__)

_TIMEOUT = 12
_TTL     = 12 * 3600  # 12 h

# Native-language security terms appended to CVE ID for each engine.
_NATIVE_TERMS = {
    "yandex": "уязвимость эксплойт PoC",   # Russian: vulnerability exploit PoC
    "baidu":  "漏洞利用 概念验证 exploit",   # Chinese: exploit proof-of-concept
    "naver":  "취약점 익스플로잇 PoC",       # Korean: vulnerability exploit PoC
}

# Known exploit/PoC hosting domains — only links to these are kept from
# search-engine result pages.
_EXPLOIT_DOMAINS = {
    "github.com",
    "gitee.com",
    "gitlab.com",
    "exploit-db.com",
    "packetstormsecurity.com",
    "seebug.org",
    "vulhub.org.cn",
    "rapid7.com",
}

_BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,ru;q=0.8,ko;q=0.7,en;q=0.6",
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
}

# Engine metadata for UI display: (display_name, flag_emoji)
ENGINE_META: dict[str, tuple[str, str]] = {
    "gitee":  ("Gitee",  "🇨🇳"),
    "seebug": ("Seebug", "🇨🇳"),
    "cnvd":   ("CNVD",   "🇨🇳"),
    "naver":  ("Naver",  "🇰🇷"),
    "yandex": ("Yandex", "🇷🇺"),
    "baidu":  ("Baidu",  "🇨🇳"),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _url_to_title(url: str) -> str:
    """Derive a readable title from a URL when no anchor text is available."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.rstrip("/")
    netloc = parsed.netloc.lstrip("www.")
    return f"{netloc}{path}" if path else netloc


def _extract_exploit_links(html: str, cve_id: str) -> list[tuple[str, str]]:
    """
    Parse search-engine HTML and return (url, title) pairs pointing to known
    exploit domains that also contain the CVE ID in the URL or anchor text.
    Handles common redirect wrappers (/url?q=..., /link?url=...).
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        seen: dict[str, str] = {}   # url → title (dedup by URL)
        cve_lower = cve_id.lower()

        for a in soup.find_all("a", href=True):
            href = a["href"]

            # Unwrap search-engine redirect URLs
            if re.search(r"[?&][qurl]=https?", href):
                m = re.search(r"[?&][qurl]=(https?[^&]+)", href)
                if m:
                    href = urllib.parse.unquote(m.group(1))

            if not href.startswith("http"):
                continue

            domain = urllib.parse.urlparse(href).netloc.lstrip("www.")
            if domain not in _EXPLOIT_DOMAINS:
                continue

            anchor = a.get_text(strip=True)
            if cve_lower not in href.lower() and cve_lower not in anchor.lower():
                continue

            if href not in seen:
                title = anchor if anchor and len(anchor) > 5 else _url_to_title(href)
                seen[href] = title

        return list(seen.items())
    except Exception:
        return []


def _source_from_url(url: str) -> PoCSource:
    if "gitee.com"               in url: return PoCSource.GITEE
    if "seebug.org"              in url: return PoCSource.SEEBUG
    if "github.com"              in url: return PoCSource.GITHUB
    if "exploit-db.com"         in url: return PoCSource.EXPLOIT_DB
    if "packetstormsecurity.com" in url: return PoCSource.PACKET_STORM
    return PoCSource.OTHER


# ── Gitee quality classification ─────────────────────────────────────────────

_GITEE_EXPLOIT_KEYWORDS = (
    "exploit", "poc", "rce", "bypass", "payload", "shell", "injection",
    "exp", "攻击", "利用", "漏洞利用", "命令执行", "远程代码", "提权",
)


def _gitee_quality(stars: int, desc: str) -> PoCQuality:
    """Classify Gitee repo quality from stars and description keywords."""
    desc_lower = desc.lower()
    is_exploit = any(k in desc_lower for k in _GITEE_EXPLOIT_KEYWORDS)
    if stars >= 10 or (stars >= 3 and is_exploit):
        return PoCQuality.FUNCTIONAL
    if stars >= 1 or is_exploit:
        return PoCQuality.CONCEPTUAL
    return PoCQuality.UNKNOWN


# ── Gitee ─────────────────────────────────────────────────────────────────────

def search_gitee(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Search Gitee (dominant Chinese code host) for PoC repositories.
    Many Chinese security researchers publish exploits here exclusively.
    """
    cache_key = _cache_mod.make_key("gitee", cve_id)
    cached    = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []
    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str] = []

    try:
        resp = http_client.scrape_noverify.get(
            "https://gitee.com/api/v5/repos/search",
            params={"q": cve_id, "sort": "stars_desc", "limit": 20},
            timeout=_TIMEOUT,
        )
        rate_limiter.record("gitee", dict(resp.headers), resp.status_code)

        if resp.status_code == 429:
            errors.append(f"[RateLimit] Gitee rate-limited for {cve_id}")
            return pocs, errors
        if not resp.is_success:
            errors.append(f"Gitee search failed ({resp.status_code}) for {cve_id}")
            return pocs, errors

        for repo in resp.json():
            name  = repo.get("name", "")
            desc  = repo.get("description") or ""
            url   = repo.get("html_url", "")
            stars = repo.get("stargazers_count", 0)
            lang  = (repo.get("language") or "").lower() or None

            if cve_id.lower() not in name.lower() and cve_id.lower() not in desc.lower():
                continue

            pocs.append(PoCRecord(
                cve_id=cve_id,
                source=PoCSource.GITEE,
                url=url,
                title=f"{name} — {desc[:80]}" if desc else name,
                description=desc[:200] if desc else None,
                stars=stars,
                quality=_gitee_quality(stars, desc),
                version_compatibility=VersionCompatibility.UNKNOWN,
                language=lang,
                raw_meta={"discovered_via": "Gitee", "engine_flag": "🇨🇳"},
            ))

    except Exception as e:
        errors.append(f"Gitee search error for {cve_id}: {e}")

    if pocs:
        _cache_mod.set(cache_key, "gitee", [p.model_dump(mode="json") for p in pocs], _TTL)
    return pocs, errors


# ── Seebug ────────────────────────────────────────────────────────────────────

def search_seebug(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Search seebug.org — curated Chinese CVE/PoC database.
    Seebug entries are manually verified and typically include working PoCs.
    """
    cache_key = _cache_mod.make_key("seebug", cve_id)
    cached    = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []
    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str] = []

    # Strip "CVE-" prefix for better Seebug search recall
    short_id = cve_id.replace("CVE-", "").replace("cve-", "")
    # Try both the search endpoint and the vuln list with search param
    urls_to_try = [
        ("https://www.seebug.org/search/", {"keywords": cve_id}),
        ("https://www.seebug.org/vuldb/vulnerabilities", {"search": short_id}),
    ]

    seen_urls: set[str] = set()
    for url, params in urls_to_try:
        try:
            resp = http_client.scrape.get(url, params=params, timeout=_TIMEOUT)
            rate_limiter.record("seebug", dict(resp.headers), resp.status_code)

            if resp.status_code == 429:
                errors.append(f"[RateLimit] Seebug rate-limited for {cve_id}")
                break
            if not resp.is_success:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            # Selector matches both /search/ and /vuldb/vulnerabilities layouts
            for a in soup.select("a.vul-title, td.vul-title-wrapper > a"):
                title = a.get_text(strip=True) or a.get("title", "")
                href  = a.get("href", "")
                if not href or not title:
                    continue
                full_url = ("https://www.seebug.org" + href) if href.startswith("/") else href
                if full_url in seen_urls:
                    continue

                # Only keep entries that mention this CVE
                if (cve_id.lower() not in title.lower()
                        and short_id not in title
                        and cve_id.lower() not in href.lower()):
                    continue

                seen_urls.add(full_url)
                pocs.append(PoCRecord(
                    cve_id=cve_id,
                    source=PoCSource.SEEBUG,
                    url=full_url,
                    title=title,
                    quality=PoCQuality.FUNCTIONAL,  # Seebug entries are curated
                    version_compatibility=VersionCompatibility.UNKNOWN,
                    raw_meta={"discovered_via": "Seebug", "engine_flag": "🇨🇳"},
                ))

        except Exception as e:
            errors.append(f"Seebug search error for {cve_id}: {e}")

    if pocs:
        _cache_mod.set(cache_key, "seebug", [p.model_dump(mode="json") for p in pocs], _TTL)
    return pocs, errors


# ── CNVD ─────────────────────────────────────────────────────────────────────

def search_cnvd(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Search CNVD (China National Vulnerability Database, cnvd.org.cn) —
    the official Chinese government vulnerability registry.
    Reliable static HTML, no bot blocking.
    """
    cache_key = _cache_mod.make_key("cnvd", cve_id)
    cached    = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []
    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str] = []

    try:
        resp = http_client.scrape_noverify.get(
            "https://www.cnvd.org.cn/flaw/list",
            params={"keywords": cve_id, "flag": "true"},
            timeout=_TIMEOUT,
        )
        rate_limiter.record("cnvd", dict(resp.headers), resp.status_code)

        if resp.status_code == 429:
            errors.append(f"[RateLimit] CNVD rate-limited for {cve_id}")
            return pocs, errors
        if not resp.is_success:
            errors.append(f"CNVD search failed ({resp.status_code}) for {cve_id}")
            return pocs, errors

        soup = BeautifulSoup(resp.text, "html.parser")
        # CNVD uses a table with class "b10" or links under .list-body
        for a in soup.select("table.b10 td a, .list-body a, .fl-list a"):
            title = a.get_text(strip=True)
            href  = a.get("href", "")
            if not href or not title or len(title) < 10:
                continue
            url = ("https://www.cnvd.org.cn" + href) if href.startswith("/") else href
            if cve_id.lower() not in title.lower() and cve_id.lower() not in url.lower():
                continue

            pocs.append(PoCRecord(
                cve_id=cve_id,
                source=PoCSource.OTHER,
                url=url,
                title=f"[CNVD] {title}",
                quality=PoCQuality.CONCEPTUAL,  # CNVD is an advisory DB, not PoC-focused
                version_compatibility=VersionCompatibility.UNKNOWN,
                raw_meta={"discovered_via": "CNVD", "engine_flag": "🇨🇳"},
            ))

    except Exception as e:
        errors.append(f"CNVD search error for {cve_id}: {e}")

    if pocs:
        _cache_mod.set(cache_key, "cnvd", [p.model_dump(mode="json") for p in pocs], _TTL)
    return pocs, errors


# ── Search-engine helper ──────────────────────────────────────────────────────

def _search_engine(
    cve_id:      str,
    engine_id:   str,
    engine_name: str,
    engine_flag: str,
    url:         str,
    params:      dict,
    allow_network: bool,
) -> tuple[list[PoCRecord], list[str]]:
    """
    Fetch one page of search results and extract links to known exploit hosts.
    Silently returns empty if the engine blocks the request (CAPTCHA / 403).
    """
    cache_key = _cache_mod.make_key(engine_id, cve_id)
    cached    = _cache_mod.get(cache_key)
    if cached is not None:
        return [PoCRecord(**r) for r in cached], []
    if not allow_network:
        return [], []

    pocs:   list[PoCRecord] = []
    errors: list[str] = []

    try:
        resp = http_client.scrape.get(url, params=params, timeout=_TIMEOUT)
        rate_limiter.record(engine_id, dict(resp.headers), resp.status_code)

        if resp.status_code in (429, 403):
            errors.append(f"[RateLimit] {engine_name} rate-limited/blocked for {cve_id}")
            return pocs, errors
        if not resp.is_success:
            return pocs, errors

        # If the engine returned a CAPTCHA page (Yandex does this), bail silently
        if "captcha" in resp.url.path.lower() or "showcaptcha" in str(resp.url).lower():
            logger.debug("%s returned CAPTCHA for %s — skipping", engine_name, cve_id)
            return pocs, errors

        for link, title in _extract_exploit_links(resp.text, cve_id):
            pocs.append(PoCRecord(
                cve_id=cve_id,
                source=_source_from_url(link),
                url=link,
                title=title,
                quality=PoCQuality.UNKNOWN,
                version_compatibility=VersionCompatibility.UNKNOWN,
                raw_meta={"discovered_via": engine_name, "engine_flag": engine_flag},
            ))

    except Exception as e:
        logger.debug("%s search error for %s: %s", engine_name, cve_id, e)

    if pocs:
        _cache_mod.set(cache_key, engine_id, [p.model_dump(mode="json") for p in pocs], _TTL)
    return pocs, errors


def search_yandex(
    cve_id: str, target_version: str, allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """Yandex search with Russian security terms (уязвимость эксплойт PoC)."""
    return _search_engine(
        cve_id, "yandex", "Yandex", "🇷🇺",
        "https://yandex.com/search/",
        {"text": f"{cve_id} {_NATIVE_TERMS['yandex']}", "lang": "ru"},
        allow_network,
    )


def search_baidu(
    cve_id: str, target_version: str, allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """Baidu search with Chinese security terms (漏洞利用 概念验证)."""
    return _search_engine(
        cve_id, "baidu", "Baidu", "🇨🇳",
        "https://www.baidu.com/s",
        {"wd": f"{cve_id} {_NATIVE_TERMS['baidu']}"},
        allow_network,
    )


def search_naver(
    cve_id: str, target_version: str, allow_network: bool = True,
) -> tuple[list[PoCRecord], list[str]]:
    """Naver search with Korean security terms (취약점 익스플로잇 PoC)."""
    return _search_engine(
        cve_id, "naver", "Naver", "🇰🇷",
        "https://search.naver.com/search.naver",
        {"query": f"{cve_id} {_NATIVE_TERMS['naver']}"},
        allow_network,
    )



# ── Orchestrator ─────────────────────────────────────────────────────────────

def run_intl_harvest(
    cve_id: str,
    target_version: str,
    allow_network: bool = True,
    skip_gitee:  bool = False,
    skip_seebug: bool = False,
    skip_cnvd:   bool = False,
    skip_yandex: bool = False,
    skip_baidu:  bool = False,
    skip_naver:  bool = False,
) -> tuple[list[PoCRecord], list[str]]:
    """Run all international harvesters in parallel for a single CVE."""
    harvesters = [
        ("gitee",  search_gitee,  skip_gitee),
        ("seebug", search_seebug, skip_seebug),
        ("cnvd",   search_cnvd,   skip_cnvd),
        ("yandex", search_yandex, skip_yandex),
        ("baidu",  search_baidu,  skip_baidu),
        ("naver",  search_naver,  skip_naver),
    ]

    all_pocs: list[PoCRecord] = []
    errors:   list[str] = []

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            pool.submit(fn, cve_id, target_version, allow_network): name
            for name, fn, skip in harvesters
            if not skip
        }
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                pocs, errs = fut.result()
                all_pocs.extend(pocs)
                errors.extend(errs)
            except Exception as e:
                errors.append(f"{name} intl harvest failed for {cve_id}: {e}")

    return all_pocs, errors
