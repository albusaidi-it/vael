"""
VAEL CLI – Stages 1, 2, 3, and AI Verdict
Usage:
    python cli/vael.py analyze --software log4j --version 2.14.1
    python cli/vael.py analyze --software log4j --version 2.14.1 --stage 2
    python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3
    python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3 --verdict
    python cli/vael.py analyze --software log4j --version 2.14.1 --stage 3 --verdict --json
"""

from __future__ import annotations

import logging
import sys
import os
from typing import Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich import box
    from rich.panel import Panel
except ImportError:
    print("Install deps: pip install typer rich httpx pydantic")
    sys.exit(1)

from core.cve_mapper import run_stage1
from core.exploit_eval import run_stage2
from core.poc_harvester import run_stage3
from core.ai_reasoner import build_verdict
from schemas.stage1 import Stage1Result, Severity
from schemas.stage2 import Stage2Result, VEPTier
from schemas.stage3 import Stage3Result, PoCQuality, VersionCompatibility

app = typer.Typer(name="vael", help="VAEL – AI-Driven Vulnerability Analysis Engine", add_completion=False)
console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red", Severity.HIGH: "red",
    Severity.MEDIUM: "yellow", Severity.LOW: "cyan",
    Severity.NONE: "dim", Severity.UNKNOWN: "dim",
}

TIER_STYLE = {
    VEPTier.T0_PATCH_NOW: ("🚨", "bold red", "PATCH NOW"),
    VEPTier.T1_HIGH:      ("⚠️ ", "red",      "HIGH"),
    VEPTier.T2_MONITOR:   ("👁️ ", "yellow",   "MONITOR"),
    VEPTier.T3_DEFER:     ("📋", "cyan",     "DEFER"),
    VEPTier.T_UNKNOWN:    ("❓", "dim",      "UNKNOWN"),
}

VERDICT_STYLE = {
    "PATCH NOW": ("🚨", "bold red"),
    "HIGH":      ("⚠️ ", "red"),
    "MONITOR":   ("👁️ ", "yellow"),
    "DEFER":     ("📋", "cyan"),
}

QUALITY_COLOR = {
    PoCQuality.WEAPONIZED: "bold red",
    PoCQuality.FUNCTIONAL: "red",
    PoCQuality.CONCEPTUAL: "yellow",
    PoCQuality.UNKNOWN:    "dim",
    PoCQuality.FAKE:       "dim",
}


def _print_stage1(result: Stage1Result) -> None:
    summary = (
        f"[bold]{result.software}[/bold] [cyan]v{result.version}[/cyan]\n"
        f"CPE: [dim]{result.cpe_string}[/dim]\n"
        f"Sources: {', '.join(result.sources_queried)}"
    )
    console.print(Panel(summary, title="[bold blue]VAEL – Stage 1: Known Vulnerability Mapping[/bold blue]"))
    console.print(
        f"\n  Total CVEs: [bold]{result.total_cves}[/bold]  |  "
        f"Critical: [bold red]{result.critical_count}[/bold red]  |  "
        f"High: [red]{result.high_count}[/red]  |  "
        f"Version-matched: [bold green]{result.version_matched_count}[/bold green]\n"
    )

    if result.cves:
        table = Table("CVE ID", "Score", "Severity", "Ver Match", "Source", "Description",
                      box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
        for cve in result.cves[:20]:
            score = cve.cvss_v3.score if cve.cvss_v3 else None
            sev = cve.cvss_v3.severity if cve.cvss_v3 else Severity.UNKNOWN
            color = SEVERITY_COLORS.get(sev, "white")
            desc = (cve.description or "")[:75]
            if cve.description and len(cve.description) > 75:
                desc += "…"
            table.add_row(
                f"[{color}]{cve.cve_id}[/{color}]",
                f"[{color}]{score:.1f}[/{color}]" if score else "[dim]N/A[/dim]",
                f"[{color}]{sev.value}[/{color}]",
                "[green]✓[/green]" if cve.version_matched else "[dim]?[/dim]",
                f"[dim]{cve.source}[/dim]",
                desc,
            )
        console.print(table)

    if result.misconfig_flags:
        console.print("\n[bold]Common Misconfigurations / CIS Flags:[/bold]")
        mstable = Table("Source", "Rule", "Title", "Severity", box=box.SIMPLE)
        for f in result.misconfig_flags:
            color = SEVERITY_COLORS.get(f.severity, "white")
            mstable.add_row(f.source, f"[dim]{f.rule_id}[/dim]", f.title,
                            f"[{color}]{f.severity.value}[/{color}]")
        console.print(mstable)


def _print_stage2(result: Stage2Result) -> None:
    console.print(Panel(
        f"[bold]{result.software}[/bold] [cyan]v{result.version}[/cyan]  —  "
        f"sources: {', '.join(result.sources_queried)}",
        title="[bold magenta]VAEL – Stage 2: Exploitability Evaluation[/bold magenta]",
    ))
    console.print(
        f"\n  🚨 [bold red]PATCH NOW: {result.t0_patch_now_count}[/bold red]  |  "
        f"⚠️  [red]HIGH: {result.t1_high_count}[/red]  |  "
        f"📊 In KEV: [bold]{result.kev_count}[/bold]  |  "
        f"⚡ EPSS > 0.5: [bold]{result.high_epss_count}[/bold]\n"
    )

    top = result.top_priority_cves(limit=15)
    if top:
        table = Table("Tier", "CVE ID", "VEP", "CVSS", "EPSS", "%ile", "KEV", "Maturity", "Patch",
                      box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
        for cve, e in top:
            icon, tier_color, tier_label = TIER_STYLE.get(e.vep_tier, ("", "white", ""))
            cvss_str = f"{cve.cvss_v3.score:.1f}" if cve.cvss_v3 and cve.cvss_v3.score else "–"
            epss_str = f"{e.epss.epss:.3f}" if e.epss else "–"
            pct_str  = f"{e.epss.percentile*100:.1f}%" if e.epss else "–"
            kev_str  = "[bold red]YES[/bold red]" if e.in_kev else "[dim]no[/dim]"
            patch_str = "[green]avail[/green]" if e.patch.patch_available else "[yellow]none[/yellow]"
            table.add_row(
                f"[{tier_color}]{icon} {tier_label}[/{tier_color}]",
                cve.cve_id, f"[{tier_color}]{e.vep_score:.0f}[/{tier_color}]",
                cvss_str, epss_str, pct_str, kev_str,
                e.exploit_maturity.value.lower().replace("_", " "), patch_str,
            )
        console.print(table)


def _print_stage3(result: Stage3Result) -> None:
    console.print(Panel(
        f"[bold]{result.software}[/bold] [cyan]v{result.version}[/cyan]  —  "
        f"sources: {', '.join(result.sources_queried) or 'none'}",
        title="[bold green]VAEL – Stage 3: Public Exploit / PoC Harvesting[/bold green]",
    ))
    console.print(
        f"\n  Total PoCs: [bold]{result.total_pocs}[/bold]  |  "
        f"Weaponized CVEs: [bold red]{result.weaponized_count}[/bold red]  |  "
        f"CVEs with compatible PoCs: [bold]{result.cves_with_compatible_pocs}[/bold]\n"
    )

    for bundle in result.bundles:
        if not bundle.pocs:
            console.print(f"  [dim]· {bundle.cve_id}: no PoCs found[/dim]")
            continue

        q_color = QUALITY_COLOR.get(bundle.best_quality, "white")
        console.print(
            f"\n  [bold]{bundle.cve_id}[/bold] "
            f"([{q_color}]{bundle.best_quality.value}[/{q_color}]) — "
            f"{bundle.total_found} PoCs, {bundle.compatible_pocs_count} compatible"
        )
        table = Table("Source", "Quality", "Compat", "Stars", "Author", "Title",
                      box=box.SIMPLE, show_header=True, header_style="dim")
        for p in bundle.pocs[:5]:
            q_color = QUALITY_COLOR.get(p.quality, "white")
            stars = str(p.stars) if p.stars is not None else "–"
            table.add_row(
                p.source.value,
                f"[{q_color}]{p.quality.value}[/{q_color}]",
                p.version_compatibility.value,
                stars,
                (p.author or "")[:20],
                (p.title or p.url)[:50],
            )
        console.print(table)


def _print_verdict(verdict) -> None:
    icon, color = VERDICT_STYLE.get(verdict.label, ("❓", "white"))
    source = "🤖 Gemini" if verdict.used_ai else "📋 Deterministic"
    header = (
        f"[{color}]{icon} {verdict.label}[/{color}]   "
        f"confidence: [bold]{verdict.confidence:.0%}[/bold]   "
        f"[dim]source: {source}[/dim]"
    )
    console.print(Panel(
        f"{header}\n\n"
        f"[bold]{verdict.recommendation}[/bold]\n\n"
        f"{verdict.reasoning_summary}",
        title="[bold]🎯 FINAL RISK VERDICT[/bold]",
        border_style=color,
    ))

    if verdict.key_evidence:
        console.print("\n[bold]Key Evidence:[/bold]")
        for ev in verdict.key_evidence:
            console.print(f"  · {ev}")


@app.command()
def analyze(
    software: str = typer.Option(..., "--software", "-s"),
    version:  str = typer.Option(..., "--version",  "-v"),
    stage:    int = typer.Option(1, "--stage", help="Run up to stage N (1, 2, or 3)"),
    verdict:  bool = typer.Option(False, "--verdict", help="Generate AI verdict (requires --stage 2+)"),
    nvd_key:  Optional[str] = typer.Option(None, "--nvd-key", envvar="NVD_API_KEY"),
    github_token: Optional[str] = typer.Option(None, "--github-token", envvar="GITHUB_TOKEN"),
    gemini_key: Optional[str] = typer.Option(None, "--gemini-key", envvar="GEMINI_API_KEY"),
    ecosystem: Optional[str] = typer.Option(None, "--ecosystem", "-e"),
    top_n:    int = typer.Option(5, "--top-n", help="Top N CVEs to harvest in Stage 3"),
    output_json: bool = typer.Option(False, "--json"),
    offline:  bool = typer.Option(False, "--offline"),
    skip_nvd: bool = typer.Option(False, "--skip-nvd"),
    skip_osv: bool = typer.Option(False, "--skip-osv"),
    skip_github: bool = typer.Option(False, "--skip-github"),
    deterministic: bool = typer.Option(False, "--deterministic",
                                       help="Skip Gemini, use rule-based verdict"),
    max_results: int = typer.Option(100, "--max"),
    verbose:  bool = typer.Option(False, "--verbose"),
) -> None:
    """Run the VAEL pipeline on a software + version."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)

    # Stage 1
    with console.status("[cyan]Stage 1: Fetching CVEs…[/cyan]"):
        s1 = run_stage1(
            software=software, version=version,
            nvd_api_key=nvd_key, osv_ecosystem=ecosystem,
            max_results_per_source=max_results,
            skip_nvd=skip_nvd, skip_osv=skip_osv,
        )

    s2 = None
    s3 = None

    if stage >= 2:
        with console.status("[magenta]Stage 2: Evaluating exploitability…[/magenta]"):
            s2 = run_stage2(s1, allow_network=not offline)

    if stage >= 3:
        if s2 is None:
            console.print("[red]Stage 3 requires Stage 2[/red]")
            sys.exit(1)
        with console.status("[green]Stage 3: Harvesting public PoCs…[/green]"):
            s3 = run_stage3(
                s2, github_token=github_token, top_n_cves=top_n,
                allow_network=not offline, skip_github=skip_github,
            )

    # JSON output mode
    if output_json:
        import json as _json
        combined = {"stage1": s1.model_dump(mode="json")}
        if s2: combined["stage2"] = s2.model_dump(mode="json")
        if s3: combined["stage3"] = s3.model_dump(mode="json")
        if verdict and s2:
            v = build_verdict(s1, s2, s3, gemini_api_key=gemini_key,
                              force_deterministic=deterministic)
            combined["verdict"] = v.model_dump(mode="json")
        print(_json.dumps(combined, indent=2, default=str))
        return

    # Human output
    _print_stage1(s1)
    if s2: console.print(); _print_stage2(s2)
    if s3: console.print(); _print_stage3(s3)

    if verdict and s2:
        with console.status("[bold magenta]Generating AI verdict…[/bold magenta]"):
            v = build_verdict(s1, s2, s3, gemini_api_key=gemini_key,
                              force_deterministic=deterministic)
        console.print()
        _print_verdict(v)


if __name__ == "__main__":
    app()
