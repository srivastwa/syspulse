from __future__ import annotations

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from syspulse.models.compliance import MappingResult
from syspulse.models.finding import Severity
from syspulse.models.report import AssessmentReport
from syspulse.models.risk import RuleMatch

console = Console()

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_TIER_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


def _tier_badge(tier: str, score: float) -> Text:
    color = _TIER_COLORS.get(tier, "white")
    return Text(f"{score}/10  [{tier}]", style=color)


def _summary_panel(report: AssessmentReport) -> Panel:
    counts = report.score.counts
    lines = Text()
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(sev, 0)
        color = _SEVERITY_COLORS.get(Severity(sev), "white")
        lines.append(f"  {sev.upper():10s}", style=color)
        lines.append(f"{count}\n")
    lines.append(f"  {'PASS':10s}", style="green")
    lines.append(f"{counts.get('pass', 0)}\n")
    return Panel(lines, title="Summary", border_style="blue", expand=False)


def _critical_panel(matches: list[RuleMatch]) -> Panel:
    critical = [m for m in matches if m.severity == Severity.CRITICAL][:5]
    text = Text()
    for i, m in enumerate(critical, 1):
        text.append(f"  {i}. ", style="dim")
        text.append(f"{m.finding.title}\n", style="bold red")
    if not critical:
        text.append("  No critical findings.", style="green")
    return Panel(text, title="Critical Findings", border_style="red", expand=False)


def _findings_table(matches: list[RuleMatch]) -> Table:
    table = Table(
        title="Findings",
        box=box.ROUNDED,
        border_style="blue",
        show_lines=False,
        expand=True,
    )
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Title", ratio=4)
    table.add_column("Severity", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("CVSS", style="dim")

    for m in matches:
        sev_style = _SEVERITY_COLORS.get(m.severity, "white")
        table.add_row(
            m.finding.id,
            m.finding.title,
            Text(m.severity.value.upper(), style=sev_style),
            f"{m.final_score:.1f}",
            (m.cvss_vector or "—")[:20],
        )
    return table


def _remediation_panel(matches: list[RuleMatch]) -> Panel:
    text = Text()
    rank = 1
    seen: set[str] = set()
    for m in matches:
        for step in m.remediation_steps:
            if step in seen:
                continue
            seen.add(step)
            text.append(f"  [{rank}] ", style="bold yellow")
            text.append(f"{step}\n")
            rank += 1
            if rank > 10:
                break
        if rank > 10:
            break
    if not seen:
        text.append("  No remediation steps available.", style="dim")
    return Panel(text, title="Remediation (top 10 by priority)", border_style="yellow")


def _compliance_table(results: list[MappingResult]) -> Table:
    table = Table(
        title="Compliance Coverage",
        box=box.ROUNDED,
        border_style="blue",
        expand=True,
    )
    table.add_column("Framework", ratio=3)
    table.add_column("Version", style="dim")
    table.add_column("Controls", justify="right")
    table.add_column("Passing", justify="right")
    table.add_column("Failing", justify="right")
    table.add_column("Not Covered", justify="right")
    table.add_column("Pass Rate", justify="right")

    for r in results:
        pass_color = "green" if r.pass_rate >= 80 else "yellow" if r.pass_rate >= 50 else "red"
        table.add_row(
            r.framework,
            r.version,
            str(r.total_controls),
            Text(str(r.passing), style="green"),
            Text(str(r.failing), style="red" if r.failing else "dim"),
            Text(str(r.not_covered), style="dim"),
            Text(f"{r.pass_rate}%", style=pass_color),
        )
    return table


def render_terminal(report: AssessmentReport) -> None:
    sys_info = report.system
    header = (
        f"[bold]SysPulse Security Assessment[/bold]  —  "
        f"[cyan]{sys_info.hostname}[/cyan]  —  "
        f"{sys_info.assessed_at.strftime('%Y-%m-%d %H:%M UTC')}"
    )
    console.print(Panel(header, border_style="blue"))
    console.print(f"  Overall Risk: ", end="")
    console.print(_tier_badge(report.score.tier, report.score.overall))
    console.print()

    console.print(Columns([
        _summary_panel(report),
        _critical_panel(report.score.ranked_matches),
    ]))
    console.print()

    console.print(_findings_table(report.score.ranked_matches))
    console.print()

    if report.compliance_results:
        console.print(_compliance_table(report.compliance_results))
        console.print()

    console.print(_remediation_panel(report.score.ranked_matches))
