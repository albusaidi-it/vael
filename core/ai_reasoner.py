"""
VAEL – AI Reasoning Layer (Gemini)

Takes structured outputs from Stages 1–3 and asks Gemini to produce:
  1. A KEV-style verdict (PATCH NOW / HIGH / MONITOR / DEFER)
  2. A confidence score (0-1)
  3. A human-readable reasoning summary

CRITICAL DESIGN PRINCIPLES:
  1. Gemini NEVER retrieves facts — all data is pre-fetched and passed in context
  2. Output is strictly schema-enforced (JSON) — Gemini fills in fields
  3. On any parsing error, fall back to deterministic rule-based verdict
  4. Temperature is low (0.2) to minimize hallucination
  5. The prompt explicitly lists the facts — Gemini "reasons over" not "retrieves"

This module is safe to disable: if no GEMINI_API_KEY is set or SDK isn't
installed, the pipeline falls back to deterministic verdicts from Stage 2.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional
from pydantic import BaseModel, Field

from schemas.stage1 import Stage1Result
from schemas.stage2 import Stage2Result, VEPTier
from schemas.stage3 import Stage3Result

logger = logging.getLogger(__name__)

GEMINI_MODEL_DEFAULT = "gemini-2.5-flash"


class RiskVerdict(BaseModel):
    """Final structured output of the reasoning layer."""
    label: str                          # "PATCH NOW" | "HIGH" | "MONITOR" | "DEFER"
    recommendation: str                 # One-line action summary
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning_summary: str              # 2-4 paragraph narrative
    key_evidence: list[str] = Field(default_factory=list)
    used_ai: bool = True                # False if fallback was used


# ── Deterministic fallback ─────────────────────────────────────────────
LABEL_BY_TIER = {
    VEPTier.T0_PATCH_NOW: "PATCH NOW",
    VEPTier.T1_HIGH:      "HIGH",
    VEPTier.T2_MONITOR:   "MONITOR",
    VEPTier.T3_DEFER:     "DEFER",
    VEPTier.T_UNKNOWN:    "MONITOR",
}

RECOMMENDATION_BY_TIER = {
    VEPTier.T0_PATCH_NOW: "Exploited in the wild — patch within 7 days.",
    VEPTier.T1_HIGH:      "Public exploit exists — patch within 30 days.",
    VEPTier.T2_MONITOR:   "Low exploitation probability — monitor and patch at next cycle.",
    VEPTier.T3_DEFER:     "No known exploits — revisit on version change.",
    VEPTier.T_UNKNOWN:    "Insufficient data — manual review recommended.",
}


def _deterministic_confidence(enrichment, cve, stage3: Optional[Stage3Result]) -> float:
    """
    Score how confident the deterministic verdict is based on available evidence.
    Each strong signal adds to a base of 0.4; capped at 0.95.
    """
    score = 0.40
    if enrichment.in_kev:
        score += 0.25           # actively exploited — very strong signal
    if enrichment.epss and enrichment.epss.epss is not None:
        score += 0.10           # quantitative probability available
    if enrichment.epss and enrichment.epss.epss > 0.5:
        score += 0.05           # high exploitation probability
    if enrichment.vep_score and enrichment.vep_score > 0:
        score += 0.05           # scored (not T_UNKNOWN)
    if cve.version_matched:
        score += 0.10           # version confirmed affected
    if stage3:
        bundle = stage3.get_bundle(enrichment.cve_id)
        if bundle and bundle.total_found > 0:
            score += 0.05       # public PoC evidence
        if bundle and bundle.compatible_pocs_count > 0:
            score += 0.05       # version-compatible PoC
    return round(min(score, 0.95), 2)


def _deterministic_verdict(stage2: Stage2Result, stage3: Optional[Stage3Result] = None) -> RiskVerdict:
    """Rule-based verdict from Stage 2 data alone. Used when Gemini is disabled or fails."""
    top = stage2.top_priority_cves(limit=1)
    if not top:
        return RiskVerdict(
            label="DEFER",
            recommendation="No CVEs found for this software/version.",
            confidence=0.6,
            reasoning_summary=f"No vulnerabilities were found for {stage2.software} {stage2.version} "
                              f"across NVD and OSV. This is either a safe version or one not yet "
                              f"indexed by public databases.",
            key_evidence=[f"Queried sources: {', '.join(stage2.sources_queried)}"],
            used_ai=False,
        )

    cve, e = top[0]
    tier = e.vep_tier

    evidence = []
    if e.in_kev:
        evidence.append(f"{cve.cve_id} is in CISA KEV catalog (exploited in the wild)")
    if e.epss:
        evidence.append(f"EPSS score: {e.epss.epss:.3f} (percentile {e.epss.percentile*100:.1f})")
    if cve.cvss_v3 and cve.cvss_v3.score:
        evidence.append(f"CVSS v3: {cve.cvss_v3.score} ({cve.cvss_v3.severity.value})")
    if cve.version_matched:
        evidence.append(f"Version {stage2.version} is confirmed affected")
    if e.patch.patch_available:
        evidence.append(f"Patch available: {', '.join(e.patch.fixed_versions[:3]) or 'see advisory'}")

    if stage3:
        bundle = stage3.get_bundle(cve.cve_id)
        if bundle and bundle.total_found > 0:
            evidence.append(
                f"Found {bundle.total_found} public PoCs "
                f"({bundle.compatible_pocs_count} version-compatible)"
            )

    narrative = (
        f"The highest-priority vulnerability in {stage2.software} {stage2.version} is {cve.cve_id}, "
        f"assigned VEP tier {tier.value} (score {e.vep_score:.0f}/100). "
        f"{cve.description[:200] if cve.description else ''} "
    )
    if e.in_kev and cve.version_matched:
        narrative += (
            "This CVE is actively exploited according to CISA, and the deployed version is "
            "confirmed to be affected. Immediate patching is recommended."
        )
    elif e.in_kev:
        narrative += (
            "This CVE is actively exploited according to CISA, though the deployed version "
            "may not be directly affected. Confirm the exact version exposure."
        )
    else:
        narrative += (
            f"This CVE has {'a functional' if e.exploit_maturity.value in ('WEAPONIZED', 'FUNCTIONAL') else 'no confirmed'} "
            f"public exploit based on current evidence."
        )

    confidence = _deterministic_confidence(e, cve, stage3)

    return RiskVerdict(
        label=LABEL_BY_TIER[tier],
        recommendation=RECOMMENDATION_BY_TIER[tier],
        confidence=confidence,
        reasoning_summary=narrative,
        key_evidence=evidence,
        used_ai=False,
    )


# ── Gemini prompt construction ─────────────────────────────────────────
def _build_prompt(
    stage1: Stage1Result,
    stage2: Stage2Result,
    stage3: Optional[Stage3Result] = None,
    top_n: int = 10,
) -> str:
    """Build a data-rich prompt with all pre-fetched facts."""
    top = stage2.top_priority_cves(limit=top_n)

    lines = [
        "You are a senior vulnerability analyst producing a KEV-style risk verdict.",
        "",
        "CRITICAL INSTRUCTIONS:",
        "- Use ONLY the facts provided below. Do not retrieve or invent information.",
        "- Do not speculate about CVEs, scores, or exploits not listed here.",
        "- If information is missing, lower the confidence score.",
        "- Output must be valid JSON matching the schema at the bottom.",
        "",
        "─── PRE-FETCHED FACTS ─────────────────────────────────────────",
        f"Target software : {stage1.software} {stage1.version}",
        f"Analysis date   : {stage2.query_ts.strftime('%Y-%m-%d %H:%M UTC')}",
        f"Data sources    : {', '.join(set(stage1.sources_queried + stage2.sources_queried))}",
        "",
        f"Total CVEs      : {stage1.total_cves}",
        f"Version-matched : {stage1.version_matched_count}",
        f"CISA KEV count  : {stage2.kev_count}",
        f"High EPSS (>0.5): {stage2.high_epss_count}",
        f"T0 PATCH-NOW    : {stage2.t0_patch_now_count}",
        f"T1 HIGH         : {stage2.t1_high_count}",
        f"T2 MONITOR      : {stage2.t2_monitor_count}",
        "",
        "─── TOP-PRIORITY CVEs (sorted by VEP score) ──────────────────",
    ]

    for i, (cve, e) in enumerate(top, 1):
        cvss      = cve.cvss_v3.score if cve.cvss_v3 else None
        cvss_vec  = cve.cvss_v3.vector if cve.cvss_v3 else None
        epss      = f"{e.epss.epss:.3f} (p{e.epss.percentile*100:.1f})" if e.epss else "n/a"
        kev_line  = f" [IN CISA KEV, added {e.kev_entry.date_added}]" if e.in_kev else ""
        patch_line = (
            f"fixed in {', '.join(e.patch.fixed_versions)}"
            if e.patch.fixed_versions else "no patch info"
        )

        # Derive attack complexity from CVSS vector for richer context
        attack_ctx = ""
        if cvss_vec:
            if "AV:N" in cvss_vec:
                attack_ctx = "network-exploitable"
            elif "AV:A" in cvss_vec:
                attack_ctx = "adjacent-network"
            elif "AV:L" in cvss_vec:
                attack_ctx = "local-only"
            if "PR:N" in cvss_vec:
                attack_ctx += ", no privileges required"
            if "UI:N" in cvss_vec:
                attack_ctx += ", no user interaction"

        lines.append(
            f"\n{i}. {cve.cve_id}{kev_line}"
            f"\n   VEP tier      : {e.vep_tier.value} (score {e.vep_score:.0f}/100)"
            f"\n   CVSS v3       : {cvss if cvss else 'n/a'}"
            + (f"  [{attack_ctx}]" if attack_ctx else "")
            + f"\n   EPSS          : {epss}"
            f"\n   Version match : {'CONFIRMED' if cve.version_matched else 'UNKNOWN'}"
            f"\n   Maturity      : {e.exploit_maturity.value}"
            f"\n   Patch         : {patch_line}"
        )
        if cve.description:
            desc = cve.description[:500].replace("\n", " ")
            lines.append(f"   Description   : {desc}")

        # Stage 3 PoC bundle
        if stage3:
            bundle = stage3.get_bundle(cve.cve_id)
            if bundle and bundle.pocs:
                lines.append(
                    f"   Public PoCs   : {bundle.total_found} total "
                    f"({bundle.compatible_pocs_count} version-compatible); "
                    f"best quality = {bundle.best_quality.value}"
                )
                for p in bundle.pocs[:5]:
                    lines.append(
                        f"     · [{p.source.value}] {p.title or p.url} "
                        f"(quality={p.quality.value}, compat={p.version_compatibility.value})"
                    )

    # Misconfig flags — all of them, not capped
    if stage1.misconfig_flags:
        lines.append("\n─── MISCONFIGURATION FLAGS ──────────────────────────────────")
        for f in stage1.misconfig_flags:
            lines.append(f"  · [{f.source}] {f.rule_id}: {f.title} ({f.severity.value})")

    lines.extend([
        "",
        "─── OUTPUT SCHEMA ────────────────────────────────────────────",
        "Respond with ONLY a JSON object matching this exact schema:",
        "{",
        '  "label": "PATCH NOW" | "HIGH" | "MONITOR" | "DEFER",',
        '  "recommendation": "<one sentence, imperative mood, includes a timeframe>",',
        '  "confidence": <float 0.0 to 1.0>,',
        '  "reasoning_summary": "<2-4 paragraphs reasoning from the facts above>",',
        '  "key_evidence": ["<fact 1>", "<fact 2>", ...]',
        "}",
        "",
        "Do not include any text outside the JSON object.",
        "Do not invent CVEs or scores not present in the facts.",
    ])

    return "\n".join(lines)


def _parse_gemini_response(text: str) -> Optional[RiskVerdict]:
    """Extract JSON from Gemini's response and validate."""
    # Strip markdown fences if present
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(l for l in lines if not l.strip().startswith("```"))

    # Find JSON object
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1:
        logger.warning("No JSON object found in Gemini response")
        return None

    try:
        data = json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse Gemini JSON: %s", e)
        return None

    # Validate label
    valid_labels = {"PATCH NOW", "HIGH", "MONITOR", "DEFER"}
    label = data.get("label", "").strip().upper()
    if label not in valid_labels:
        logger.warning("Invalid label from Gemini: %s", label)
        return None

    try:
        return RiskVerdict(
            label=label,
            recommendation=data.get("recommendation", ""),
            confidence=float(data.get("confidence", 0.5)),
            reasoning_summary=data.get("reasoning_summary", ""),
            key_evidence=data.get("key_evidence", []) or [],
            used_ai=True,
        )
    except (ValueError, TypeError) as e:
        logger.warning("Invalid Gemini verdict fields: %s", e)
        return None


def call_gemini(
    prompt: str,
    api_key: str,
    model: str = GEMINI_MODEL_DEFAULT,
    timeout: int = 60,
) -> Optional[str]:
    """
    Call Gemini API using google-generativeai SDK.
    Returns raw response text or None on failure.

    Requires: pip install google-generativeai
    """
    try:
        import google.generativeai as genai
    except ImportError:
        logger.warning("google-generativeai not installed; skipping AI reasoning")
        return None

    try:
        genai.configure(api_key=api_key)
        gen_model = genai.GenerativeModel(
            model_name=model,
            generation_config={
                "temperature": 0.2,
                "top_p": 0.9,
                "max_output_tokens": 2048,
                "response_mime_type": "application/json",
            },
        )
        response = gen_model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error("Gemini call failed: %s", e)
        return None


def build_verdict(
    stage1: Stage1Result,
    stage2: Stage2Result,
    stage3: Optional[Stage3Result] = None,
    gemini_api_key: Optional[str] = None,
    gemini_model: str = GEMINI_MODEL_DEFAULT,
    force_deterministic: bool = False,
) -> RiskVerdict:
    """
    Build the final KEV-style risk verdict.

    Tries Gemini first. Falls back to deterministic reasoning on any failure
    (missing API key, missing SDK, API error, parse error).
    """
    from core.config import settings
    api_key = gemini_api_key or settings.effective_gemini_key()

    if force_deterministic or not api_key:
        if not api_key:
            logger.info("No Gemini API key — using deterministic verdict")
        return _deterministic_verdict(stage2, stage3)

    prompt = _build_prompt(stage1, stage2, stage3)
    raw = call_gemini(prompt, api_key, model=gemini_model)
    if not raw:
        logger.info("Gemini unavailable — falling back to deterministic verdict")
        return _deterministic_verdict(stage2, stage3)

    verdict = _parse_gemini_response(raw)
    if not verdict:
        logger.info("Gemini response invalid — falling back to deterministic verdict")
        return _deterministic_verdict(stage2, stage3)

    return verdict
