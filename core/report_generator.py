"""
VAEL – Markdown Report Generator
Converts Stage 1-3 results + AI verdict into a structured markdown report.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from schemas.stage1 import Stage1Result, Severity
from schemas.stage2 import Stage2Result, VEPTier
from schemas.stage3 import Stage3Result, PoCQuality
from core.ai_reasoner import RiskVerdict

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🟢",
    Severity.NONE:     "⚪",
    Severity.UNKNOWN:  "⚫",
}

_VEP_EMOJI = {
    VEPTier.T0_PATCH_NOW: "🚨",
    VEPTier.T1_HIGH:      "🔴",
    VEPTier.T2_MONITOR:   "🟡",
    VEPTier.T3_DEFER:     "🟢",
    VEPTier.T_UNKNOWN:    "⚫",
}

_VERDICT_EMOJI = {
    "PATCH NOW": "🚨",
    "HIGH":      "🔴",
    "MONITOR":   "🟡",
    "DEFER":     "🟢",
}

_QUALITY_EMOJI = {
    PoCQuality.WEAPONIZED:   "💣",
    PoCQuality.FUNCTIONAL:   "⚡",
    PoCQuality.CONCEPTUAL:   "📄",
    PoCQuality.FAKE:         "🗑️",
    PoCQuality.UNKNOWN:      "❓",
}


def generate_report(
    s1: Stage1Result,
    s2: Stage2Result,
    s3: Optional[Stage3Result],
    verdict: RiskVerdict,
    include_toc: bool = True,
) -> str:
    lines: list[str] = []

    def h(level: int, text: str) -> None:
        lines.append(f"{'#' * level} {text}")
        lines.append("")

    def p(text: str) -> None:
        lines.append(text)
        lines.append("")

    def hr() -> None:
        lines.append("---")
        lines.append("")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    verdict_icon = _VERDICT_EMOJI.get(verdict.label, "⚫")

    # Title
    h(1, f"VAEL Security Report — {s1.software} {s1.version}")
    p(f"*Generated: {ts} | VAEL v0.5.0*")
    hr()

    # TOC
    if include_toc:
        h(2, "Table of Contents")
        lines.append("1. [Executive Summary](#executive-summary)")
        lines.append("2. [Stage 1 — CVE Inventory](#stage-1--cve-inventory)")
        lines.append("3. [Stage 2 — Exploitability Assessment](#stage-2--exploitability-assessment)")
        if s3:
            lines.append("4. [Stage 3 — Public PoC Inventory](#stage-3--public-poc-inventory)")
        lines.append("5. [AI Verdict & Recommendations](#ai-verdict--recommendations)")
        lines.append("")
        hr()

    # Executive Summary
    h(2, "Executive Summary")

    conf_pct = int(verdict.confidence * 100)
    ai_tag = "AI-assisted (Gemini)" if verdict.used_ai else "Deterministic"
    p(
        f"| | |\n"
        f"|---|---|\n"
        f"| **Software** | `{s1.software} {s1.version}` |\n"
        f"| **Verdict** | {verdict_icon} **{verdict.label}** |\n"
        f"| **Confidence** | {conf_pct}% ({ai_tag}) |\n"
        f"| **Total CVEs** | {s1.total_cves} |\n"
        f"| **Critical** | {s1.critical_count} |\n"
        f"| **KEV-listed** | {s2.kev_count} |\n"
        f"| **Patch-Now tier** | {s2.t0_patch_now_count} |\n"
        f"| **Public PoCs** | {s3.total_pocs if s3 else 'N/A'} |"
    )

    p(f"> **{verdict.label}**: {verdict.recommendation}")

    hr()

    # Stage 1
    h(2, "Stage 1 — CVE Inventory")
    p(f"Sources queried: {', '.join(s1.sources_queried) or 'none'}")

    if not s1.cves:
        p("*No CVEs found.*")
    else:
        header = "| CVE ID | Severity | CVSS v3 | Version Match | CWEs |"
        sep    = "|--------|----------|---------|---------------|------|"
        lines.append(header)
        lines.append(sep)
        for cve in sorted(
            s1.cves,
            key=lambda c: (c.cvss_v3.score if c.cvss_v3 and c.cvss_v3.score else 0),
            reverse=True,
        ):
            sev = cve.cvss_v3.severity if cve.cvss_v3 else Severity.UNKNOWN
            icon = _SEVERITY_EMOJI.get(sev, "⚫")
            score = f"{cve.cvss_v3.score:.1f}" if cve.cvss_v3 and cve.cvss_v3.score else "N/A"
            matched = "✅ Yes" if cve.version_matched else "No"
            cwes = ", ".join(c.cwe_id for c in cve.cwes) or "—"
            lines.append(f"| [{cve.cve_id}](https://nvd.nist.gov/vuln/detail/{cve.cve_id}) | {icon} {sev.value} | {score} | {matched} | {cwes} |")
        lines.append("")

    if s1.errors:
        p(f"**Errors:** {'; '.join(s1.errors)}")

    hr()

    # Stage 2
    h(2, "Stage 2 — Exploitability Assessment")
    p(f"Sources queried: {', '.join(s2.sources_queried) or 'none'}")

    if not s2.enrichments:
        p("*No enrichment data.*")
    else:
        header = "| CVE ID | VEP Tier | EPSS | KEV | Maturity | Patch |"
        sep    = "|--------|----------|------|-----|----------|-------|"
        lines.append(header)
        lines.append(sep)
        for enr in sorted(s2.enrichments, key=lambda e: e.vep_score, reverse=True):
            tier_icon = _VEP_EMOJI.get(enr.vep_tier, "⚫")
            epss_str = f"{enr.epss.epss:.1%}" if enr.epss else "—"
            kev_str = "✅ Yes" if enr.in_kev else "No"
            maturity = enr.exploit_maturity.value
            patch = "✅ Yes" if enr.patch.patch_available else "No"
            lines.append(
                f"| [{enr.cve_id}](https://nvd.nist.gov/vuln/detail/{enr.cve_id}) "
                f"| {tier_icon} {enr.vep_tier.value} | {epss_str} | {kev_str} "
                f"| {maturity} | {patch} |"
            )
        lines.append("")

    # Top priority detail blocks
    top = s2.top_priority_cves(limit=3)
    if top:
        h(3, "Top Priority CVEs")
        for cve_rec, enr in top:
            sev = cve_rec.cvss_v3.severity if cve_rec.cvss_v3 else Severity.UNKNOWN
            icon = _SEVERITY_EMOJI.get(sev, "⚫")
            h(4, f"{icon} {cve_rec.cve_id}")
            if cve_rec.description:
                p(f"*{cve_rec.description[:300]}{'...' if len(cve_rec.description) > 300 else ''}*")
            if enr.reasoning:
                lines.append("**Evidence:**")
                for r in enr.reasoning:
                    lines.append(f"- {r}")
                lines.append("")
            if enr.patch.fixed_versions:
                p(f"**Fix:** Upgrade to `{', '.join(enr.patch.fixed_versions[:3])}`")

    if s2.errors:
        p(f"**Errors:** {'; '.join(s2.errors)}")

    hr()

    # Stage 3
    if s3:
        h(2, "Stage 3 — Public PoC Inventory")
        p(f"Sources queried: {', '.join(s3.sources_queried) or 'none'}")
        p(
            f"**{s3.total_pocs}** public exploits found across **{len(s3.bundles)}** CVEs — "
            f"**{s3.weaponized_count}** weaponized, "
            f"**{s3.cves_with_compatible_pocs}** CVEs with version-compatible PoCs."
        )

        for bundle in sorted(s3.bundles, key=lambda b: len(b.pocs), reverse=True):
            if not bundle.pocs:
                continue
            q_icon = _QUALITY_EMOJI.get(bundle.best_quality, "❓")
            h(3, f"{q_icon} {bundle.cve_id} — {bundle.total_found} PoC(s)")
            header = "| Source | Title | Quality | Compat. | Stars | Lang |"
            sep    = "|--------|-------|---------|---------|-------|------|"
            lines.append(header)
            lines.append(sep)
            for poc in sorted(bundle.pocs, key=lambda p: (p.quality.value, p.stars or 0), reverse=True):
                q_em = _QUALITY_EMOJI.get(poc.quality, "❓")
                stars = str(poc.stars) if poc.stars is not None else "—"
                lang = poc.language or "—"
                compat = poc.version_compatibility.value
                title_link = f"[{poc.title or poc.url[:40]}]({poc.url})"
                lines.append(
                    f"| {poc.source.value} | {title_link} | {q_em} {poc.quality.value} "
                    f"| {compat} | {stars} | {lang} |"
                )
            lines.append("")

        if s3.errors:
            p(f"**Errors:** {'; '.join(s3.errors)}")

        hr()

    # AI Verdict
    h(2, "AI Verdict & Recommendations")

    p(
        f"**Verdict:** {verdict_icon} `{verdict.label}`  \n"
        f"**Confidence:** {conf_pct}%  \n"
        f"**Method:** {ai_tag}"
    )

    h(3, "Recommendation")
    p(verdict.recommendation)

    h(3, "Analysis")
    for para in verdict.reasoning_summary.split("\n\n"):
        p(para.strip())

    if verdict.key_evidence:
        h(3, "Key Evidence")
        for ev in verdict.key_evidence:
            lines.append(f"- {ev}")
        lines.append("")

    hr()
    p("*Report generated by [VAEL](https://github.com/your-org/vael) — Vulnerability Analysis Engine v0.5.0*")

    return "\n".join(lines)


def save_report(
    s1: Stage1Result,
    s2: Stage2Result,
    s3: Optional[Stage3Result],
    verdict: RiskVerdict,
    output_path: Optional[str] = None,
) -> str:
    """Generate and save a markdown report. Returns the path written."""
    report = generate_report(s1, s2, s3, verdict)
    if output_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_path = f"vael_report_{s1.software}_{s1.version}_{ts}.md"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    return output_path
