"""
VAEL – Central API Rate Limit Tracker

Tracks real remaining quota for every external API by reading the
standard rate-limit response headers returned by each provider.

Supported APIs and their header schemes:
  GitHub (REST + GraphQL)
      X-RateLimit-Remaining  : requests left in window
      X-RateLimit-Limit      : window ceiling
      X-RateLimit-Reset      : epoch seconds when window resets
      X-RateLimit-Used       : consumed in this window

  NVD
      No standard headers — tracks 403 responses as exhaustion signal

  Shodan / Censys / VulnCheck / OSV
      Track HTTP 429 responses as exhaustion signals

Usage anywhere in the codebase:
    from core.rate_limiter import rate_limiter

    # After every HTTP response:
    rate_limiter.record("github", response.headers, response.status_code)

    # Before a request:
    warn = rate_limiter.check("github")
    if warn: logger.warning(warn)

    # From the API layer:
    rate_limiter.status()   # → dict for /rate-limits endpoint
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── Per-API static configuration ──────────────────────────────────────────────

@dataclass
class APILimits:
    """Static configuration for one external API."""
    name: str
    window_seconds: int          # rolling window duration
    limit_no_key: int            # requests per window without auth
    limit_with_key: int          # requests per window with auth
    warn_threshold: float = 0.15 # warn when ≤15% of budget remains
    header_remaining: str = ""   # response header name for remaining count
    header_limit: str    = ""    # response header name for ceiling
    header_reset: str    = ""    # response header name for reset epoch


_API_CONFIG: dict[str, APILimits] = {
    "nvd": APILimits(
        name="NVD",
        window_seconds=30,
        limit_no_key=5,
        limit_with_key=50,
        warn_threshold=0.2,
        # NVD does not send standard rate-limit headers; 403 = rate limited
    ),
    "github": APILimits(
        name="GitHub REST",
        window_seconds=3600,
        limit_no_key=60,
        limit_with_key=5000,
        warn_threshold=0.1,
        header_remaining="x-ratelimit-remaining",
        header_limit="x-ratelimit-limit",
        header_reset="x-ratelimit-reset",
    ),
    "github_search": APILimits(
        name="GitHub Search",
        window_seconds=60,
        limit_no_key=10,
        limit_with_key=30,
        warn_threshold=0.2,
        header_remaining="x-ratelimit-remaining",
        header_limit="x-ratelimit-limit",
        header_reset="x-ratelimit-reset",
    ),
    "ghsa": APILimits(
        name="GHSA GraphQL",
        window_seconds=3600,
        limit_no_key=60,
        limit_with_key=5000,
        warn_threshold=0.1,
        header_remaining="x-ratelimit-remaining",
        header_limit="x-ratelimit-limit",
        header_reset="x-ratelimit-reset",
    ),
    "osv": APILimits(
        name="OSV",
        window_seconds=60,
        limit_no_key=1000,    # OSV is very generous; track 429s only
        limit_with_key=1000,
        warn_threshold=0.05,
    ),
    "vulncheck": APILimits(
        name="VulnCheck",
        window_seconds=3600,
        limit_no_key=0,       # no key → no access
        limit_with_key=100,   # community tier estimate
        warn_threshold=0.2,
    ),
    "shodan": APILimits(
        name="Shodan",
        window_seconds=86400,   # daily credits
        limit_no_key=0,
        limit_with_key=100,     # free tier: 100 search credits/month ~= 3/day
        warn_threshold=0.3,
    ),
    "censys": APILimits(
        name="Censys",
        window_seconds=86400 * 30,  # monthly quota
        limit_no_key=0,
        limit_with_key=250,
        warn_threshold=0.2,
    ),
    "fofa": APILimits(
        name="FOFA",
        window_seconds=86400 * 30,  # monthly quota
        limit_no_key=0,
        limit_with_key=10000,       # F plan: 10k queries/month
        warn_threshold=0.1,
        header_remaining="x-fofa-quota-remaining",
    ),
    "zoomeye": APILimits(
        name="ZoomEye",
        window_seconds=86400 * 30,  # monthly quota
        limit_no_key=0,
        limit_with_key=10000,       # free tier: 10k results/month
        warn_threshold=0.1,
    ),
    "cnvd": APILimits(
        name="CNVD (China NVD)",
        window_seconds=60,
        limit_no_key=10,
        limit_with_key=10,
        warn_threshold=0.3,
    ),
    "packet_storm": APILimits(
        name="Packet Storm",
        window_seconds=60,
        limit_no_key=10,
        limit_with_key=10,  # no auth concept; 10 req/min to stay polite
        warn_threshold=0.3,
    ),
    "gitee": APILimits(
        name="Gitee",
        window_seconds=3600,
        limit_no_key=60,    # unauthenticated
        limit_with_key=5000,
        warn_threshold=0.1,
        header_remaining="x-ratelimit-remaining",
        header_limit="x-ratelimit-limit",
        header_reset="x-ratelimit-reset",
    ),
    "seebug": APILimits(
        name="Seebug",
        window_seconds=60,
        limit_no_key=10,
        limit_with_key=10,
        warn_threshold=0.3,
    ),
    "yandex": APILimits(
        name="Yandex Search",
        window_seconds=60,
        limit_no_key=5,
        limit_with_key=5,
        warn_threshold=0.4,
    ),
    "baidu": APILimits(
        name="Baidu Search",
        window_seconds=60,
        limit_no_key=5,
        limit_with_key=5,
        warn_threshold=0.4,
    ),
    "naver": APILimits(
        name="Naver Search",
        window_seconds=60,
        limit_no_key=5,
        limit_with_key=5,
        warn_threshold=0.4,
    ),
    "attackerkb": APILimits(
        name="AttackerKB (Rapid7)",
        window_seconds=86400,
        limit_no_key=0,         # no key → not used
        limit_with_key=100,     # conservative estimate for free tier
        warn_threshold=0.2,
    ),
    "pastebin": APILimits(
        name="Pastebin",
        window_seconds=60,
        limit_no_key=5,
        limit_with_key=5,       # no auth; be polite
        warn_threshold=0.4,
    ),
}


# ── Runtime state for one API ──────────────────────────────────────────────────

@dataclass
class APIState:
    api_id: str
    remaining: Optional[int] = None   # from last response header
    limit: Optional[int]     = None   # from last response header
    reset_at: Optional[int]  = None   # epoch seconds
    request_count: int        = 0     # tracked locally this session
    throttled_count: int      = 0     # times we got 429/403
    last_seen: Optional[float] = None # time.time() of last response
    is_exhausted: bool         = False

    def remaining_pct(self, has_key: bool = True) -> Optional[float]:
        if self.remaining is not None and self.limit and self.limit > 0:
            return self.remaining / self.limit
        # Fall back to local counting
        cfg = _API_CONFIG.get(self.api_id)
        if cfg is None:
            return None
        ceiling = cfg.limit_with_key if has_key else cfg.limit_no_key
        if ceiling <= 0:
            return None
        used = self.request_count % max(ceiling, 1)
        return max(0.0, (ceiling - used) / ceiling)

    def reset_in_seconds(self) -> Optional[int]:
        if self.reset_at:
            return max(0, int(self.reset_at - time.time()))
        return None

    def status_label(self, has_key: bool = True) -> str:
        if self.is_exhausted:
            reset = self.reset_in_seconds()
            return f"EXHAUSTED (resets in {reset}s)" if reset else "EXHAUSTED"
        pct = self.remaining_pct(has_key)
        if pct is None:
            return "UNKNOWN"
        if pct > 0.5:
            return "OK"
        if pct > 0.15:
            return "LOW"
        return "CRITICAL"


# ── Tracker ────────────────────────────────────────────────────────────────────

class RateLimitTracker:
    """Thread-safe per-API rate limit tracker."""

    def __init__(self) -> None:
        self._lock   = threading.Lock()
        self._states: dict[str, APIState] = {
            api_id: APIState(api_id=api_id)
            for api_id in _API_CONFIG
        }

    def _state(self, api_id: str) -> APIState:
        if api_id not in self._states:
            self._states[api_id] = APIState(api_id=api_id)
        return self._states[api_id]

    def record(
        self,
        api_id: str,
        headers: dict,
        status_code: int,
    ) -> None:
        """
        Call after every HTTP response. Reads rate-limit headers and updates
        the budget tracker. Also flags 429/403 as exhaustion events.
        """
        cfg = _API_CONFIG.get(api_id)
        with self._lock:
            state = self._state(api_id)
            state.request_count += 1
            state.last_seen = time.time()

            # Read standard headers (lower-case for httpx compatibility)
            if cfg and cfg.header_remaining:
                raw = headers.get(cfg.header_remaining) or headers.get(cfg.header_remaining.upper())
                if raw is not None:
                    try:
                        state.remaining = int(raw)
                    except ValueError:
                        pass

            if cfg and cfg.header_limit:
                raw = headers.get(cfg.header_limit) or headers.get(cfg.header_limit.upper())
                if raw is not None:
                    try:
                        state.limit = int(raw)
                    except ValueError:
                        pass

            if cfg and cfg.header_reset:
                raw = headers.get(cfg.header_reset) or headers.get(cfg.header_reset.upper())
                if raw is not None:
                    try:
                        state.reset_at = int(raw)
                    except ValueError:
                        pass

            if status_code in (429, 403):
                state.throttled_count += 1
                state.is_exhausted = True
                logger.warning(
                    "API rate limit hit: %s (HTTP %d, total throttle events: %d)",
                    api_id, status_code, state.throttled_count,
                )
            elif status_code < 400 and state.is_exhausted:
                # Successful response after exhaustion means window reset
                state.is_exhausted = False

    def check(self, api_id: str, has_key: bool = True) -> Optional[str]:
        """
        Call before making a request.
        Returns a warning string if budget is low, None if OK.
        """
        cfg = _API_CONFIG.get(api_id)
        if cfg is None:
            return None

        with self._lock:
            state = self._state(api_id)

        if state.is_exhausted:
            reset = state.reset_in_seconds()
            reset_msg = f" Resets in {reset}s." if reset else ""
            return (
                f"{cfg.name} rate limit exhausted.{reset_msg} "
                f"Results may be incomplete."
            )

        pct = state.remaining_pct(has_key)
        if pct is None:
            return None

        if pct <= cfg.warn_threshold:
            remaining = state.remaining if state.remaining is not None else "?"
            reset = state.reset_in_seconds()
            reset_msg = f" Window resets in {reset}s." if reset else ""
            return (
                f"{cfg.name} rate limit low: {remaining} requests remaining "
                f"({pct:.0%} of budget).{reset_msg}"
            )
        return None

    def warn_and_log(self, api_id: str, has_key: bool = True) -> Optional[str]:
        """check() + log the warning if present."""
        msg = self.check(api_id, has_key)
        if msg:
            logger.warning("[RateLimit] %s", msg)
        return msg

    def status(self, key_config: Optional[dict[str, bool]] = None) -> dict:
        """
        Return a status dict suitable for the /rate-limits API endpoint.
        key_config: {api_id: has_key} — if omitted, assumes no keys.
        """
        out: dict[str, dict] = {}
        for api_id, cfg in _API_CONFIG.items():
            has_key = (key_config or {}).get(api_id, False)
            with self._lock:
                state = self._state(api_id)

            reset_in = state.reset_in_seconds()
            pct      = state.remaining_pct(has_key)
            out[api_id] = {
                "name":             cfg.name,
                "status":           state.status_label(has_key),
                "remaining":        state.remaining,
                "limit":            state.limit or (cfg.limit_with_key if has_key else cfg.limit_no_key),
                "used_this_session": state.request_count,
                "throttle_events":  state.throttled_count,
                "reset_in_seconds": reset_in,
                "pct_remaining":    round(pct * 100, 1) if pct is not None else None,
                "has_key":          has_key,
                "tip":              _upgrade_tip(api_id, has_key),
            }
        return out

    def collect_warnings(self, api_ids: list[str], has_key_map: dict[str, bool]) -> list[str]:
        """Collect all active warnings for a set of APIs. Used to attach to pipeline results."""
        warnings: list[str] = []
        for api_id in api_ids:
            msg = self.check(api_id, has_key_map.get(api_id, False))
            if msg:
                warnings.append(msg)
        return warnings


def _upgrade_tip(api_id: str, has_key: bool) -> str:
    tips = {
        "nvd":          ("Set NVD_API_KEY for 10× higher rate limit (50 req/30s vs 5)",
                         ""),
        "github":       ("Set GITHUB_TOKEN for 83× higher rate limit (5000 req/hr vs 60)",
                         ""),
        "github_search":("Set GITHUB_TOKEN for 3× higher search limit (30 req/min vs 10)",
                         ""),
        "ghsa":         ("Set GITHUB_TOKEN for 83× higher GHSA limit",
                         ""),
        "vulncheck":    ("Set VULNCHECK_API_KEY at vulncheck.com/register (free community tier)",
                         "VulnCheck key configured"),
        "shodan":       ("Set SHODAN_API_KEY at shodan.io for internet exposure data",
                         ""),
        "censys":       ("Set CENSYS_API_ID + CENSYS_API_SECRET at censys.io for exposure data",
                         ""),
        "osv":          ("", ""),
    }
    no_key_tip, has_key_tip = tips.get(api_id, ("", ""))
    return has_key_tip if has_key else no_key_tip


# ── Global singleton ───────────────────────────────────────────────────────────
rate_limiter = RateLimitTracker()
