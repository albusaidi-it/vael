#!/usr/bin/env python3
"""
VAEL – Interactive Demo Script
Runs the full pipeline against offline fixtures with Rich terminal output.

Usage:
    python demo/run_demo.py                   # interactive picker
    python demo/run_demo.py log4shell         # direct scenario
    python demo/run_demo.py spring4shell
    python demo/run_demo.py --report          # also write markdown report
"""

from __future__ import annotations

import sys
import os
import time
import argparse
from typing import Optional

# Allow running from repo root or from demo/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.columns import Columns
    from rich.rule import Rule
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.padding import Padding
    from rich import box
except ImportError:
    print("ERROR: 'rich' is required. Run: pip install rich")
    sys.exit(1)

from core.fixtures import list_fixtures, load_fixture_by_id, DEMO_SCENARIOS
from core.report_generator import save_report
from schemas.stage2 import VEPTier
from schemas.stage3 import PoCQuality

console = Console()

# ── Colour maps ───────────────────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "NONE":     "dim",
    "UNKNOWN":  "dim",
}
VEP_COLOR = {
    VEPTier.T0_PATCH_NOW: "bold red",
    VEPTier.T1_HIGH:      "bold yellow",
    VEPTier.T2_MONITOR:   "yellow",
    VEPTier.T3_DEFER:     "green",
    VEPTier.T_UNKNOWN:    "dim",
}
VEP_LABEL = {
    VEPTier.T0_PATCH_NOW: "PATCH NOW",
    VEPTier.T1_HIGH:      "HIGH",
    VEPTier.T2_MONITOR:   "MONITOR",
    VEPTier.T3_DEFER:     "DEFER",
    VEPTier.T_UNKNOWN:    "UNKNOWN",
}
QUALITY_COLOR = {
    PoCQuality.WEAPONIZED:   "bold red",
    PoCQuality.FUNCTIONAL:   "yellow",
    PoCQuality.CONCEPTUAL:   "cyan",
    PoCQuality.FAKE:         "dim",
    PoCQuality.UNKNOWN:      "dim",
}
VERDICT_COLOR = {
    "PATCH NOW": "bold red",
    "HIGH":      "bold yellow",
    "MONITOR":   "yellow",
    "DEFER":     "bold green",
}


def banner() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold cyan]V[/bold cyan][bold white]AEL[/bold white]  "
        "[dim]Vulnerability Analysis Engine[/dim]  [dim]v0.3.0[/dim]",
        border_style="cyan",
        padding=(0, 4),
    ))
    console.print()


def pick_scenario() -> Optional[str]:
    available = list_fixtures()
    if not available:
        console.print("[red]No fixture files found in fixtures/ directory.[/red]")
        return None

    console.print("[bold]Available demo scenarios:[/bold]\n")
    for i, s in enumerate(available, 1):
        console.print(f"  [cyan]{i}.[/cyan] {s['label']}")
    console.print(f"  [cyan]{len(available)+1}.[/cyan] [dim]Exit[/dim]")
    console.print()

    while True:
        try:
            raw = input("  Select scenario [1]: ").strip() or "1"
            choice = int(raw)
            if choice == len(available) + 1:
                return None
            if 1 <= choice <= len(available):
                return available[choice - 1]["id"]
        except (ValueError, KeyboardInterrupt):
            return None
        console.print("  [red]Invalid choice — enter a number from the list.[/red]")


def fake_progress(label: str, duration: float = 0.6) -> None:
    with Progress(
        SpinnerColumn(spinner_name="dots"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as prog:
        prog.add_task(label, total=None)
        time.sleep(duration)


def render_stage1(result) -> None:
    console.print(Rule("[bold]Stage 1 — CVE Inventory[/bold]", style="blue"))
    console.print()

    # Summary chips
    chips = [
        f"[dim]Total:[/dim] [bold]{result.total_cves}[/bold]",
        f"[dim]Critical:[/dim] [bold red]{result.critical_count}[/bold red]",
        f"[dim]High:[/dim] [bold yellow]{result.high_count}[/bold yellow]",
        f"[dim]Version-matched:[/dim] [bold]{result.version_matched_count}[/bold]",
        f"[dim]Sources:[/dim] {', '.join(result.sources_queried)}",
    ]
    console.print("  " + "   ·   ".join(chips))
    console.print()

    if not result.cves:
        console.print("  [dim]No CVEs found.[/dim]")
        return

    tbl = Table(box=box.ROUNDED, border_style="dim", show_header=True, header_style="bold dim")
    tbl.add_column("CVE ID",     style="cyan",  no_wrap=True)
    tbl.add_column("Severity",   no_wrap=True)
    tbl.add_column("CVSS v3",    justify="right", no_wrap=True)
    tbl.add_column("✓ Version",  justify="center", no_wrap=True)
    tbl.add_column("CWEs",       style="dim")
    tbl.add_column("Description (truncated)", max_width=55, overflow="ellipsis")

    sorted_cves = sorted(
        result.cves,
        key=lambda c: (c.cvss_v3.score if c.cvss_v3 and c.cvss_v3.score else 0),
        reverse=True,
    )
    for cve in sorted_cves:
        sev = cve.cvss_v3.severity.value if cve.cvss_v3 else "UNKNOWN"
        score = f"{cve.cvss_v3.score:.1f}" if cve.cvss_v3 and cve.cvss_v3.score else "—"
        matched = "[green]✓[/green]" if cve.version_matched else "[dim]—[/dim]"
        cwes = ", ".join(c.cwe_id for c in cve.cwes) or "—"
        desc = (cve.description or "")[:100]
        tbl.add_row(
            cve.cve_id,
            Text(sev, style=SEV_COLOR.get(sev, "")),
            score, matched, cwes, desc,
        )

    console.print(Padding(tbl, (0, 2)))
    console.print()


def render_stage2(result) -> None:
    console.print(Rule("[bold]Stage 2 — Exploitability[/bold]", style="blue"))
    console.print()

    chips = [
        f"[dim]KEV:[/dim] [bold red]{result.kev_count}[/bold red]",
        f"[dim]High EPSS (>50%):[/dim] [bold]{result.high_epss_count}[/bold]",
        f"[dim]Patch-Now tier:[/dim] [bold red]{result.t0_patch_now_count}[/bold red]",
        f"[dim]High tier:[/dim] [bold yellow]{result.t1_high_count}[/bold yellow]",
    ]
    console.print("  " + "   ·   ".join(chips))
    console.print()

    if not result.enrichments:
        console.print("  [dim]No enrichment data.[/dim]")
        return

    tbl = Table(box=box.ROUNDED, border_style="dim", show_header=True, header_style="bold dim")
    tbl.add_column("CVE ID",    style="cyan", no_wrap=True)
    tbl.add_column("VEP Tier",  no_wrap=True)
    tbl.add_column("Score",     justify="right", no_wrap=True)
    tbl.add_column("EPSS",      justify="right", no_wrap=True)
    tbl.add_column("KEV",       justify="center", no_wrap=True)
    tbl.add_column("Maturity",  no_wrap=True)
    tbl.add_column("Patch",     no_wrap=True)

    sorted_enr = sorted(result.enrichments, key=lambda e: e.vep_score, reverse=True)
    for enr in sorted_enr:
        tier_str = VEP_LABEL.get(enr.vep_tier, enr.vep_tier.value)
        tier_col = VEP_COLOR.get(enr.vep_tier, "")
        epss_str = f"{enr.epss.epss:.1%}" if enr.epss else "—"
        kev_str  = "[bold red]✓ KEV[/bold red]" if enr.in_kev else "[dim]—[/dim]"
        patch_str = (
            f"[green]✓[/green] {enr.patch.fixed_versions[0]}"
            if enr.patch.patch_available and enr.patch.fixed_versions
            else ("[green]✓[/green]" if enr.patch.patch_available else "[dim]—[/dim]")
        )
        tbl.add_row(
            enr.cve_id,
            Text(tier_str, style=tier_col),
            f"{enr.vep_score:.1f}", epss_str, kev_str,
            enr.exploit_maturity.value, patch_str,
        )

    console.print(Padding(tbl, (0, 2)))

    # Show reasoning for top CVE
    top = sorted_enr[0] if sorted_enr else None
    if top and top.reasoning:
        console.print()
        console.print(f"  [bold]Top priority — {top.cve_id} reasoning:[/bold]")
        for r in top.reasoning:
            console.print(f"    [dim]→[/dim] {r}")
    console.print()


def render_stage3(result) -> None:
    console.print(Rule("[bold]Stage 3 — Public PoCs[/bold]", style="blue"))
    console.print()

    if not result or not result.total_pocs:
        console.print("  [dim]No public exploits found.[/dim]")
        console.print()
        return

    chips = [
        f"[dim]Total:[/dim] [bold]{result.total_pocs}[/bold]",
        f"[dim]Weaponized:[/dim] [bold red]{result.weaponized_count}[/bold red]",
        f"[dim]CVEs w/ PoC:[/dim] [bold]{result.cves_with_compatible_pocs}[/bold]",
        f"[dim]Sources:[/dim] {', '.join(result.sources_queried)}",
    ]
    console.print("  " + "   ·   ".join(chips))
    console.print()

    tbl = Table(box=box.ROUNDED, border_style="dim", show_header=True, header_style="bold dim")
    tbl.add_column("CVE ID",   style="cyan", no_wrap=True)
    tbl.add_column("Quality",  no_wrap=True)
    tbl.add_column("Source",   no_wrap=True)
    tbl.add_column("⭐",       justify="right", no_wrap=True)
    tbl.add_column("Lang",     no_wrap=True)
    tbl.add_column("Compat.",  no_wrap=True)
    tbl.add_column("Title / URL", max_width=50, overflow="ellipsis")

    all_pocs = sorted(
        [p for b in result.bundles for p in b.pocs],
        key=lambda p: {PoCQuality.WEAPONIZED:4, PoCQuality.FUNCTIONAL:3,
                       PoCQuality.CONCEPTUAL:2, PoCQuality.UNKNOWN:1, PoCQuality.FAKE:0}
                      .get(p.quality, 0),
        reverse=True,
    )
    for poc in all_pocs:
        q_str = poc.quality.value
        q_col = QUALITY_COLOR.get(poc.quality, "")
        stars = str(poc.stars) if poc.stars is not None else "—"
        tbl.add_row(
            poc.cve_id,
            Text(q_str, style=q_col),
            poc.source.value,
            stars,
            poc.language or "—",
            poc.version_compatibility.value,
            poc.title or poc.url,
        )

    console.print(Padding(tbl, (0, 2)))
    console.print()


def render_verdict(verdict) -> None:
    console.print(Rule("[bold]AI Verdict[/bold]", style="blue"))
    console.print()

    v_color = VERDICT_COLOR.get(verdict.label, "bold white")
    conf_pct = int(verdict.confidence * 100)
    method = "Gemini AI" if verdict.used_ai else "Deterministic"

    console.print(Panel(
        f"[{v_color}]{verdict.label}[/{v_color}]\n\n"
        f"[dim]Confidence:[/dim] {conf_pct}%  [dim]·[/dim]  [dim]Method:[/dim] {method}\n\n"
        f"{verdict.recommendation}",
        border_style=v_color.replace("bold ", ""),
        padding=(1, 3),
    ))
    console.print()

    if verdict.key_evidence:
        console.print("  [bold]Key evidence:[/bold]")
        for ev in verdict.key_evidence:
            console.print(f"    [dim]→[/dim] {ev}")
        console.print()

    console.print("  [bold]Analysis:[/bold]")
    for para in verdict.reasoning_summary.split("\n\n"):
        console.print(Padding(para.strip(), (0, 4)))
        console.print()


def run_demo(scenario_id: str, write_report: bool = False) -> None:
    banner()

    # Find scenario metadata
    scenario = next((s for s in DEMO_SCENARIOS if s["id"] == scenario_id), None)
    if scenario:
        console.print(f"  [bold]Scenario:[/bold] {scenario['label']}")
        console.print(f"  [bold]Target:[/bold]   [cyan]{scenario['software']} {scenario['version']}[/cyan]")
    console.print()

    fake_progress("Stage 1 — mapping CVEs from NVD + OSV…", 0.7)
    fake_progress("Stage 2 — fetching EPSS scores + CISA KEV…", 0.5)
    fake_progress("Stage 3 — harvesting PoCs from GitHub + Exploit-DB + Nuclei…", 0.6)
    fake_progress("Generating verdict…", 0.3)

    fixture = load_fixture_by_id(scenario_id)
    if fixture is None:
        console.print(f"[red]Fixture '{scenario_id}' not found. Check fixtures/ directory.[/red]")
        sys.exit(1)

    s1, s2, s3, verdict = fixture

    render_stage1(s1)
    render_stage2(s2)
    render_stage3(s3)
    render_verdict(verdict)

    if write_report:
        path = save_report(s1, s2, s3, verdict)
        console.print(f"  [green]✓ Report written:[/green] [cyan]{path}[/cyan]")
        console.print()

    console.print(Rule(style="dim"))
    console.print(f"  [dim]Demo complete. Start the API with:[/dim]  [cyan]uvicorn api.main:app --reload[/cyan]")
    console.print(f"  [dim]Then open:[/dim]  [cyan]web/index.html[/cyan]  [dim]in your browser.[/dim]")
    console.print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VAEL offline demo — runs the full pipeline against fixture data.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(
            [f"  {s['id']:<20} {s['label']}" for s in DEMO_SCENARIOS]
        ),
    )
    parser.add_argument(
        "scenario", nargs="?", default=None,
        help="Scenario ID (e.g. log4shell, spring4shell). Omit for interactive picker.",
    )
    parser.add_argument(
        "--report", action="store_true",
        help="Write a markdown report file after the demo.",
    )
    args = parser.parse_args()

    scenario_id = args.scenario
    if scenario_id is None:
        banner()
        scenario_id = pick_scenario()
        if scenario_id is None:
            console.print("\n  [dim]Bye.[/dim]\n")
            sys.exit(0)
        # Clear screen and re-run with chosen scenario
        console.clear()

    run_demo(scenario_id, write_report=args.report)


if __name__ == "__main__":
    main()
