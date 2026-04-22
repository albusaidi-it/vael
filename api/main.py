"""
VAEL REST API – Stages 1-3 + AI Verdict
Run: uvicorn api.main:app --reload

Endpoints:
    POST /analyze           → Stage1Result
    POST /analyze/exploit   → Stage2Result (runs Stages 1+2)
    POST /analyze/pocs      → Stage3Result (runs Stages 1+2+3)
    POST /analyze/full      → All stages + AI verdict
    GET  /health
    GET  /docs
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.cve_mapper import run_stage1
from core.exploit_eval import run_stage2
from core.poc_harvester import run_stage3
from core.ai_reasoner import build_verdict, RiskVerdict
from schemas.stage1 import Stage1Result
from schemas.stage2 import Stage2Result
from schemas.stage3 import Stage3Result

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="VAEL – Vulnerability Analysis Engine",
    description="AI-driven vulnerability analysis: CVE mapping → exploit intel → PoC harvesting → AI verdict",
    version="0.3.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


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
    verdict: RiskVerdict


@app.get("/health")
def health():
    return {"status": "ok", "stages": [1, 2, 3], "version": "0.3.0",
            "ai_enabled": bool(os.environ.get("GEMINI_API_KEY"))}


@app.post("/analyze", response_model=Stage1Result)
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


@app.post("/analyze/exploit", response_model=Stage2Result)
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


@app.post("/analyze/pocs", response_model=Stage3Result)
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


@app.post("/analyze/full", response_model=FullAnalysisResponse)
def analyze_full(req: FullAnalysisRequest):
    """Full pipeline: all stages + AI verdict. This is the flagship endpoint."""
    _validate(req)
    try:
        s1 = run_stage1(
            software=req.software.strip(), version=req.version.strip(),
            cpe_string=req.cpe_string, osv_ecosystem=req.ecosystem,
            max_results_per_source=req.max_results,
            skip_nvd=req.skip_nvd, skip_osv=req.skip_osv,
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
        return FullAnalysisResponse(stage1=s1, stage2=s2, stage3=s3, verdict=verdict)
    except Exception as e:
        logger.exception("Full pipeline error")
        raise HTTPException(500, detail=str(e))


def _validate(req: AnalyzeRequest) -> None:
    if not req.software.strip() or not req.version.strip():
        raise HTTPException(400, detail="software and version are required")
