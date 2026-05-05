"""
VAEL – Centralised settings via pydantic-settings.

All optional API keys and tuneable knobs live here.
Load order (highest priority first):
  1. Environment variables
  2. .env file in CWD (or VAEL_ENV_FILE path)
  3. Docker /run/secrets/{name} files
  4. Defaults

Usage anywhere in the codebase:
    from core.config import settings
    key = settings.nvd_api_key
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret_file(name: str) -> Optional[str]:
    """Read a Docker /run/secrets/{name} file if it exists."""
    p = Path(f"/run/secrets/{name.lower()}")
    if p.exists():
        return p.read_text().strip() or None
    return None


class VAELSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=os.environ.get("VAEL_ENV_FILE", ".env"),
        env_file_encoding="utf-8",
        env_prefix="",          # keys match env vars directly (NVD_API_KEY, etc.)
        extra="ignore",
        case_sensitive=False,
    )

    # ── Cache ──────────────────────────────────────────────────────────────
    cache_dir: Path = Path("./feeds")
    cache_db: str = "vael_cache.db"  # SQLite filename inside cache_dir

    # ── API keys (all optional) ────────────────────────────────────────────
    nvd_api_key: Optional[str] = None
    github_token: Optional[str] = None
    gemini_api_key: Optional[str] = None
    google_api_key: Optional[str] = None   # fallback alias for gemini_api_key
    vulncheck_api_key: Optional[str] = None
    shodan_api_key: Optional[str] = None
    censys_api_id: Optional[str] = None
    censys_api_secret: Optional[str] = None
    serpapi_key: Optional[str] = None       # web search fallback
    tavily_api_key: Optional[str] = None    # web search fallback
    fofa_api_key: Optional[str] = None      # fofa.info internet intelligence
    fofa_email: Optional[str] = None        # fofa.info account email (required with key)
    zoomeye_api_key: Optional[str] = None   # zoomeye.ai internet intelligence
    attackerkb_api_key: Optional[str] = None  # Rapid7 AttackerKB community exploitability API

    # ── Pipeline tunables ─────────────────────────────────────────────────
    gemini_model: str = "gemini-2.5-flash"
    max_nvd_results: int = 200
    max_osv_results: int = 100
    stage3_top_n: int = 10
    allow_network: bool = True

    # ── Server / deployment ────────────────────────────────────────────────
    # Comma-separated allowed origins, e.g. "https://app.example.com,https://admin.example.com"
    allow_origins: str = "*"
    # Set to true in production to hide /docs and /redoc
    disable_docs: bool = False
    log_level: str = "INFO"
    # Number of gunicorn/uvicorn worker processes
    vael_workers: int = 2

    def effective_gemini_key(self) -> Optional[str]:
        return self.gemini_api_key or self.google_api_key

    def cache_db_path(self) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir / self.cache_db

    def _apply_secret_files(self) -> None:
        """Pull Docker secrets if env vars are missing."""
        for field in ("nvd_api_key", "github_token", "gemini_api_key",
                      "vulncheck_api_key", "shodan_api_key"):
            if not getattr(self, field):
                val = _read_secret_file(field)
                if val:
                    object.__setattr__(self, field, val)


def _load_settings() -> VAELSettings:
    s = VAELSettings()
    s._apply_secret_files()
    return s


settings: VAELSettings = _load_settings()
