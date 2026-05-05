"""
VAEL API – Analysis routes.
  POST /analyze
  POST /analyze/exploit
  POST /analyze/pocs
  POST /analyze/full
  GET  /analyze/stream
  POST /analyze/exposure
  POST /analyze/sbom
  POST /analyze/oman
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Generator, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.config import settings
from core.cve_mapper import run_stage1
from core.exploit_eval import run_stage2
from core.poc_harvester import run_stage3
from core.ai_reasoner import build_verdict, RiskVerdict
from schemas.stage1 import Stage1Result
from schemas.stage2 import Stage2Result
from schemas.stage3 import Stage3Result
from schemas.stage4 import Stage4Result
from core import cache as _cache

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Analysis"])


# ── Request / Response models ─────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    software: str
    version: str
    cpe_string: Optional[str] = None
    ecosystem: Optional[str] = None
    max_results: int = 100
    skip_nvd: bool = False
    skip_osv: bool = False

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"software": "log4j", "version": "2.14.1"},
                {"software": "nginx", "version": "1.20.0"},
            ]
        }
    }


class ExploitRequest(AnalyzeRequest):
    offline: bool = False


class PoCRequest(ExploitRequest):
    top_n: int = 5
    github_token: Optional[str] = None
    skip_github: bool = False


class FullAnalysisRequest(PoCRequest):
    gemini_api_key: Optional[str] = None
    deterministic: bool = False


class FullAnalysisResponse(BaseModel):
    stage1: Stage1Result
    stage2: Stage2Result
    stage3: Optional[Stage3Result] = None
    stage4: Optional[Stage4Result] = None
    verdict: RiskVerdict


class SBOMAnalysisSummary(BaseModel):
    total_components: int
    components_analyzed: int
    results: list[FullAnalysisResponse]
    errors: list[str]


class OmanIntelRequest(BaseModel):
    software: str
    version: str
    cve_ids: Optional[list[str]] = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"software": "apache", "version": "2.4.50"},
                {"software": "log4j", "version": "2.14.1",
                 "cve_ids": ["CVE-2021-44228"]},
            ]
        }
    }


def _validate(req: AnalyzeRequest) -> None:
    if not req.software.strip() or not req.version.strip():
        raise HTTPException(400, detail="software and version are required")


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=Stage1Result)
def analyze(req: AnalyzeRequest):
    _validate(req)
    try:
        return run_stage1(
            software=req.software.strip(), version=req.version.strip(),
            cpe_string=req.cpe_string, osv_ecosystem=req.ecosystem,
            max_results_per_source=req.max_results,
            skip_nvd=req.skip_nvd, skip_osv=req.skip_osv,
        )
    except Exception as e:
        logger.exception("Stage 1 error")
        raise HTTPException(500, detail=str(e))


@router.post("/analyze/exploit", response_model=Stage2Result)
def analyze_exploit(req: ExploitRequest):
    _validate(req)
    try:
        s1 = run_stage1(
            software=req.software.strip(), version=req.version.strip(),
            cpe_string=req.cpe_string, osv_ecosystem=req.ecosystem,
            max_results_per_source=req.max_results,
            skip_nvd=req.skip_nvd, skip_osv=req.skip_osv,
        )
        return run_stage2(s1, allow_network=not req.offline)
    except Exception as e:
        logger.exception("Stage 2 error")
        raise HTTPException(500, detail=str(e))


@router.post("/analyze/pocs", response_model=Stage3Result)
def analyze_pocs(req: PoCRequest):
    _validate(req)
    try:
        s1 = run_stage1(
            software=req.software.strip(), version=req.version.strip(),
            cpe_string=req.cpe_string, osv_ecosystem=req.ecosystem,
            max_results_per_source=req.max_results,
            skip_nvd=req.skip_nvd, skip_osv=req.skip_osv,
        )
        s2 = run_stage2(s1, allow_network=not req.offline)
        return run_stage3(
            s2, github_token=req.github_token, top_n_cves=req.top_n,
            allow_network=not req.offline, skip_github=req.skip_github,
        )
    except Exception as e:
        logger.exception("Stage 3 error")
        raise HTTPException(500, detail=str(e))


@router.post("/analyze/full", response_model=FullAnalysisResponse)
def analyze_full(req: FullAnalysisRequest):
    """Full pipeline: all stages + AI verdict. This is the flagship endpoint."""
    _validate(req)

    # Pipeline-level cache: skip for partial/offline runs so we never cache
    # incomplete results.  Also skip if any source is explicitly disabled.
    _use_cache = not req.offline and not req.skip_nvd and not req.skip_osv
    _p_key = (
        _cache.pipeline_cache_key(
            req.software.strip(), req.version.strip(),
            req.ecosystem or "", req.deterministic, req.top_n,
        )
        if _use_cache else None
    )
    if _p_key:
        _hit = _cache.get(_p_key)
        if _hit:
            try:
                logger.debug("Pipeline cache HIT for %s %s", req.software, req.version)
                return FullAnalysisResponse.model_validate(_hit)
            except Exception:
                pass  # corrupt/stale entry — fall through and recompute

    try:
        s1 = run_stage1(
            software=req.software.strip(), version=req.version.strip(),
            cpe_string=req.cpe_string, osv_ecosystem=req.ecosystem,
            max_results_per_source=req.max_results,
            skip_nvd=req.skip_nvd, skip_osv=req.skip_osv,
            nvd_api_key=settings.nvd_api_key,
            attackerkb_api_key=settings.attackerkb_api_key,
        )
        s2 = run_stage2(s1, allow_network=not req.offline)
        s3 = None
        if not req.skip_github or req.top_n > 0:
            s3 = run_stage3(
                s2, github_token=req.github_token, top_n_cves=req.top_n,
                allow_network=not req.offline, skip_github=req.skip_github,
            )
        verdict = build_verdict(
            s1, s2, s3,
            gemini_api_key=req.gemini_api_key,
            force_deterministic=req.deterministic,
        )
        result = FullAnalysisResponse(stage1=s1, stage2=s2, stage3=s3, verdict=verdict)
        if _p_key:
            try:
                _cache.set(_p_key, "pipeline", result.model_dump(mode="json"), _cache._PIPELINE_TTL)
                logger.debug("Pipeline cache SET for %s %s (TTL=%ds)",
                             req.software, req.version, _cache._PIPELINE_TTL)
            except Exception as ce:
                logger.debug("Pipeline cache write failed: %s", ce)
        return result
    except Exception as e:
        logger.exception("Full pipeline error")
        raise HTTPException(500, detail=str(e))


@router.get("/analyze/stream")
def analyze_stream(
    software: str = Query(..., description="Software name, e.g. log4j"),
    version: str = Query(..., description="Version string, e.g. 2.14.1"),
    top_n: int = Query(10, description="Top-N CVEs to harvest PoCs for"),
    offline: bool = Query(False),
    skip_nvd: bool = Query(False),
    skip_osv: bool = Query(False),
    skip_github: bool = Query(False),
    github_token: Optional[str] = Query(None),
    gemini_api_key: Optional[str] = Query(None),
    deterministic: bool = Query(False),
):
    """
    Full pipeline with Server-Sent Events. Each stage emits one SSE event
    as soon as it finishes so the UI can render progressively.

    On a cache hit the full result is served from SQLite and all four events
    are emitted in rapid succession (sub-100 ms round trip).

    Event stream format:
        event: stage1\\ndata: <Stage1Result JSON>\\n\\n
        event: stage2\\ndata: <Stage2Result JSON>\\n\\n
        event: stage3\\ndata: <Stage3Result JSON>\\n\\n
        event: verdict\\ndata: <RiskVerdict JSON>\\n\\n
        event: done\\ndata: {}\\n\\n
        event: error\\ndata: {"message": "..."}\\n\\n
    """
    if not software.strip() or not version.strip():
        raise HTTPException(400, detail="software and version are required")

    _use_cache = not offline and not skip_nvd and not skip_osv
    _p_key = (
        _cache.pipeline_cache_key(software.strip(), version.strip(), "", deterministic, top_n)
        if _use_cache else None
    )

    def _event(name: str, payload) -> str:
        if hasattr(payload, "model_dump_json"):
            data = payload.model_dump_json()
        else:
            data = json.dumps(payload)
        return f"event: {name}\ndata: {data}\n\n"

    def _stream() -> Generator[str, None, None]:
        # ── Cache hit path: emit all events from SQLite, no upstream calls ──
        if _p_key:
            _hit = _cache.get(_p_key)
            if _hit:
                try:
                    cached = FullAnalysisResponse.model_validate(_hit)
                    logger.debug("SSE pipeline cache HIT for %s %s", software, version)
                    yield _event("stage1",  cached.stage1)
                    yield _event("stage2",  cached.stage2)
                    if cached.stage3:
                        yield _event("stage3", cached.stage3)
                    yield _event("verdict", cached.verdict)
                    yield "event: done\ndata: {}\n\n"
                    return
                except Exception:
                    pass  # corrupt entry — fall through to live run

        # ── Live pipeline run ──────────────────────────────────────────────
        try:
            s1 = run_stage1(
                software=software.strip(), version=version.strip(),
                skip_nvd=skip_nvd, skip_osv=skip_osv,
                nvd_api_key=settings.nvd_api_key,
                attackerkb_api_key=settings.attackerkb_api_key,
            )
            yield _event("stage1", s1)

            s2 = run_stage2(s1, allow_network=not offline)
            yield _event("stage2", s2)

            s3 = run_stage3(
                s2,
                github_token=github_token,
                top_n_cves=top_n,
                allow_network=not offline,
                skip_github=skip_github,
            )
            yield _event("stage3", s3)

            verdict = build_verdict(
                s1, s2, s3,
                gemini_api_key=gemini_api_key,
                force_deterministic=deterministic,
            )
            yield _event("verdict", verdict)

            # Store full result before signalling done
            if _p_key:
                try:
                    full = FullAnalysisResponse(stage1=s1, stage2=s2, stage3=s3, verdict=verdict)
                    _cache.set(_p_key, "pipeline", full.model_dump(mode="json"), _cache._PIPELINE_TTL)
                    logger.debug("SSE pipeline cache SET for %s %s", software, version)
                except Exception as ce:
                    logger.debug("SSE pipeline cache write failed: %s", ce)

            yield "event: done\ndata: {}\n\n"

        except Exception as e:
            logger.exception("SSE pipeline error")
            yield _event("error", {"message": str(e)})

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/analyze/exposure", response_model=Stage4Result)
def analyze_exposure(req: ExploitRequest):
    """Stage 4: Internet exposure check via Shodan + Censys (requires API keys)."""
    _validate(req)
    try:
        from core.exposure_checker import run_stage4
        s1 = run_stage1(software=req.software.strip(), version=req.version.strip())
        s2 = run_stage2(s1, allow_network=not req.offline)
        return run_stage4(s2, cpe=s1.cpe_string)
    except Exception as e:
        logger.exception("Stage 4 error")
        raise HTTPException(500, detail=str(e))


@router.post("/analyze/sbom", response_model=SBOMAnalysisSummary)
async def analyze_sbom(
    file: UploadFile = File(..., description="SBOM file (CycloneDX JSON/XML, SPDX JSON/.spdx, requirements.txt)"),
    top_n: int = Query(5),
    offline: bool = Query(False),
    skip_github: bool = Query(False),
    deterministic: bool = Query(True),
):
    """
    Parse a SBOM file and run the full VAEL pipeline for each component.
    Returns one FullAnalysisResponse per component (Stage1+2+3+verdict).
    Large SBOMs are capped at 20 components to stay within rate limits.
    """
    import os as _os
    import tempfile
    from core.sbom_parser import parse_sbom

    suffix = Path(file.filename or "bom.json").suffix
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        components = parse_sbom(tmp_path)
    except Exception as e:
        raise HTTPException(400, detail=f"SBOM parse error: {e}")
    finally:
        _os.unlink(tmp_path)

    if not components:
        raise HTTPException(400, detail="No components found in SBOM")

    MAX_COMPONENTS = 20
    to_analyze = components[:MAX_COMPONENTS]
    results: list[FullAnalysisResponse] = []
    errors: list[str] = []

    import asyncio

    async def _analyze_component(comp):
        s1 = await asyncio.to_thread(
            run_stage1, software=comp.name, version=comp.version,
            osv_ecosystem=comp.ecosystem, skip_nvd=offline, skip_osv=offline,
        )
        s2 = await asyncio.to_thread(run_stage2, s1, allow_network=not offline)
        s3 = await asyncio.to_thread(
            run_stage3, s2, top_n_cves=top_n,
            allow_network=not offline, skip_github=skip_github,
        )
        verdict = await asyncio.to_thread(
            build_verdict, s1, s2, s3, force_deterministic=deterministic,
        )
        return FullAnalysisResponse(stage1=s1, stage2=s2, stage3=s3, verdict=verdict)

    for comp in to_analyze:
        try:
            results.append(await _analyze_component(comp))
        except Exception as e:
            errors.append(f"{comp.display()}: {e}")
            logger.warning("SBOM component analysis failed: %s %s: %s", comp.name, comp.version, e)

    return SBOMAnalysisSummary(
        total_components=len(components),
        components_analyzed=len(results),
        results=results,
        errors=errors,
    )


@router.post("/analyze/oman")
def analyze_oman(req: OmanIntelRequest):
    """
    Oman Internet Exposure Intelligence.

    Queries Shodan, FOFA, and Censys — filtered to Oman (country:OM) — for
    CVE-based exposure of the specified software.
    """
    software = req.software.strip()
    version  = req.version.strip()
    if not software or not version:
        raise HTTPException(400, detail="software and version are required")

    cve_ids    = list(req.cve_ids or [])
    cve_source = "user_provided" if cve_ids else "none"

    if not cve_ids:
        try:
            from core.nvd_fetcher import fetch_nvd
            records, _ = fetch_nvd(
                software, version,
                api_key=settings.nvd_api_key,
                max_results=20,
            )
            records.sort(
                key=lambda r: (r.cvss_v3.score if r.cvss_v3 else 0),
                reverse=True,
            )
            cve_ids    = [r.cve_id for r in records[:5] if r.cve_id]
            cve_source = "auto_nvd" if cve_ids else "none"
            logger.info("Oman intel: auto-fetched %d CVEs for %s %s: %s",
                        len(cve_ids), software, version, cve_ids)
        except Exception as exc:
            logger.warning("Oman intel: CVE auto-fetch failed: %s", exc)

    try:
        from core.oman_intel import run_oman_intel
        result = run_oman_intel(
            software=software,
            version=version,
            cve_ids=cve_ids,
            cve_source=cve_source,
        )
        return result
    except Exception as e:
        logger.exception("Oman intel error")
        raise HTTPException(500, detail=str(e))
