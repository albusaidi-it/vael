"""
VAEL REST API – Stages 1-3 + AI Verdict
Run: uvicorn api.main:app --reload

Endpoints:
    GET  /                  → Web UI (web/index.html)
    POST /analyze           → Stage1Result
    POST /analyze/exploit   → Stage2Result (runs Stages 1+2)
    POST /analyze/pocs      → Stage3Result (runs Stages 1+2+3)
    POST /analyze/full      → All stages + AI verdict
    GET  /analyze/stream    → SSE full pipeline
    GET  /health
    GET  /docs
"""

from __future__ import annotations

import asyncio
import contextvars
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import settings
from api.routes import analyze, system, demo, monitor

# ── Request ID context ────────────────────────────────────────────────────────

_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="-"
)


class _RequestIDFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get("-")  # type: ignore[attr-defined]
        return True


logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format=(
        '{"time":"%(asctime)s","level":"%(levelname)s",'
        '"req":"%(request_id)s","logger":"%(name)s","msg":"%(message)s"}'
    ),
    datefmt="%Y-%m-%dT%H:%M:%S",
)
for _h in logging.root.handlers:
    _h.addFilter(_RequestIDFilter())

logger = logging.getLogger(__name__)


# ── Background feed pre-warmer ────────────────────────────────────────────────

async def _feed_warmer() -> None:
    """
    Hourly background task that refreshes EPSS and KEV feeds before they go
    stale.  Each fetcher's internal TTL check is a cheap SQL SELECT when the
    feed is fresh, so this loop is nearly free on most ticks.

    This prevents the first user query after a 24-hour gap from blocking while
    ~200 K EPSS rows download in the foreground.
    """
    await asyncio.sleep(30)   # short initial delay so startup isn't delayed
    while True:
        try:
            from core.epss_fetcher import lookup_epss
            from core.kev_fetcher import lookup_kev
            await asyncio.to_thread(lookup_epss, [])
            await asyncio.to_thread(lookup_kev,  [])
            logger.debug("Background feed warmer: EPSS + KEV checked")
        except Exception as exc:
            logger.warning("Background feed warmer error: %s", exc)
        await asyncio.sleep(3600)   # check again in 1 hour


@asynccontextmanager
async def _lifespan(app: FastAPI):
    task = asyncio.create_task(_feed_warmer())
    logger.info("Background feed warmer started")
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ── App factory ───────────────────────────────────────────────────────────────

_origins = [o.strip() for o in settings.allow_origins.split(",") if o.strip()]
_docs_url = None if settings.disable_docs else "/docs"
_redoc_url = None if settings.disable_docs else "/redoc"

app = FastAPI(
    title="VAEL – Vulnerability Analysis Engine",
    description="AI-driven vulnerability analysis: CVE mapping → exploit intel → PoC harvesting → AI verdict",
    version="0.5.0",
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    lifespan=_lifespan,
)


class _RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        token = _request_id_var.set(req_id)
        t0 = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            _request_id_var.reset(token)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        logger.info(
            "%s %s → %d  (%dms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed_ms,
        )
        response.headers["X-Request-ID"] = req_id
        return response


app.add_middleware(_RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

_WEB_DIR = Path(__file__).parent.parent / "web"
if _WEB_DIR.exists():
    app.mount("/web", StaticFiles(directory=str(_WEB_DIR)), name="web")

app.include_router(analyze.router)
app.include_router(system.router)
app.include_router(demo.router)
app.include_router(monitor.router)


@app.get("/", include_in_schema=False)
def root():
    index = _WEB_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return RedirectResponse("/docs")
