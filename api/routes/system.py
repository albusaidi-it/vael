"""
VAEL API – System / operational routes.
  GET  /health
  GET  /rate-limits
  GET  /cache/stats
  DELETE /cache
  GET  /config/keys/status
"""
from __future__ import annotations

from fastapi import APIRouter

from core.config import settings

router = APIRouter()


@router.get("/health")
def health():
    from core.rate_limiter import rate_limiter
    key_map = {
        "nvd": bool(settings.nvd_api_key),
        "github": bool(settings.github_token),
        "github_search": bool(settings.github_token),
        "ghsa": bool(settings.github_token),
        "vulncheck": bool(settings.vulncheck_api_key),
        "shodan": bool(settings.shodan_api_key),
        "censys": bool(settings.censys_api_id),
        "osv": False,
    }
    rl = rate_limiter.status(key_map)
    exhausted = [k for k, v in rl.items() if v["status"] == "EXHAUSTED"]
    critical  = [k for k, v in rl.items() if v["status"] == "CRITICAL"]
    return {
        "status": "degraded" if exhausted else "ok",
        "stages": [1, 2, 3, 4],
        "version": "0.4.0",
        "ai_enabled": bool(settings.effective_gemini_key()),
        "rate_limits": {
            "exhausted_apis": exhausted,
            "critical_apis":  critical,
            "all_ok":         not exhausted and not critical,
        },
    }


@router.get("/rate-limits", tags=["Config"])
def rate_limits():
    """Live rate limit status for every external API."""
    from core.rate_limiter import rate_limiter
    key_map = {
        "nvd":           bool(settings.nvd_api_key),
        "github":        bool(settings.github_token),
        "github_search": bool(settings.github_token),
        "ghsa":          bool(settings.github_token),
        "osv":           False,
        "vulncheck":     bool(settings.vulncheck_api_key),
        "shodan":        bool(settings.shodan_api_key),
        "censys":        bool(settings.censys_api_id),
    }
    return rate_limiter.status(key_map)


@router.get("/cache/stats", tags=["Config"])
def cache_stats():
    """SQLite cache statistics per data source."""
    from core.cache import stats, purge_expired
    purge_expired()
    return stats()


@router.delete("/cache", tags=["Config"])
def cache_purge():
    """Purge all expired cache entries."""
    from core.cache import purge_expired
    deleted = purge_expired()
    return {"deleted": deleted}


@router.get("/config/keys/status", tags=["Config"])
def keys_status():
    """Show which optional API keys are configured (values never exposed)."""
    def _status(val):
        if not val:
            return {"configured": False}
        masked = val[:4] + "…" + val[-4:] if len(val) > 8 else "****"
        return {"configured": True, "masked": masked}

    return {
        "nvd_api_key":          _status(settings.nvd_api_key),
        "github_token":         _status(settings.github_token),
        "gemini_api_key":       _status(settings.effective_gemini_key()),
        "vulncheck_api_key":    _status(settings.vulncheck_api_key),
        "shodan_api_key":       _status(settings.shodan_api_key),
        "censys_api_id":        _status(settings.censys_api_id),
        "tavily_api_key":       _status(settings.tavily_api_key),
        "attackerkb_api_key":   _status(settings.attackerkb_api_key),
    }
