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


def _inventory_panel(report: AssessmentReport) -> Panel:
    inv = report.inventory
    text = Text()
    if inv is None:
        text.append("  No inventory collected.", style="dim")
        return Panel(text, title="System Inventory", border_style="blue", expand=False)

    # CPU
    for cpu in inv.cpu:
        ghz = f"{cpu.max_clock_speed_mhz / 1000:.1f} GHz" if cpu.max_clock_speed_mhz else ""
        text.append("  CPU   ", style="dim")
        text.append(f"{cpu.name}  {ghz}  {cpu.cores}C/{cpu.logical_processors}T\n")

    # RAM
    text.append("  RAM   ", style="dim")
    text.append(f"{inv.total_ram_gb} GB")
    if inv.memory_modules:
        speeds = sorted({m.speed_mhz for m in inv.memory_modules if m.speed_mhz})
        if speeds:
            text.append(f"  ({speeds[-1]} MHz)")
    text.append("\n")

    # Disks
    for disk in inv.disks:
        text.append("  Disk  ", style="dim")
        text.append(f"{disk.model}  {disk.size_gb} GB")
        if disk.media_type:
            text.append(f"  [{disk.media_type}]", style="dim")
        text.append("\n")

    # GPU
    for gpu in inv.display_adapters:
        text.append("  GPU   ", style="dim")
        text.append(f"{gpu.name}")
        if gpu.vram_mb:
            text.append(f"  {gpu.vram_mb} MB VRAM", style="dim")
        text.append("\n")

    # Software & users counts
    text.append("  SW    ", style="dim")
    text.append(f"{len(inv.software)} installed packages\n")
    text.append("  Users ", style="dim")
    text.append(f"{len(inv.user_accounts)} local accounts\n")
    if inv.security_agents:
        categories = sorted({a.category for a in inv.security_agents})
        text.append("  Sec   ", style="dim")
        for cat in categories:
            agents = [a for a in inv.security_agents if a.category == cat]
            running = sum(1 for a in agents if a.status == "running")
            label = f"{cat}({running}/{len(agents)}) "
            text.append(label, style="green" if running else "yellow")
        text.append("\n")

    if inv.browser_extensions:
        browsers = sorted({e.browser for e in inv.browser_extensions})
        text.append("  Exts  ", style="dim")
        for br in browsers:
            count = sum(1 for e in inv.browser_extensions if e.browser == br)
            text.append(f"{br.title()}: {count}  ")
        text.append("\n")

    if inv.network_hosts:
        text.append("  Net   ", style="dim")
        text.append(f"{len(inv.network_hosts)} hosts discovered\n")
        for h in inv.network_hosts[:8]:
            label = h.hostname or h.netbios_name or h.ip
            os_tag = f"[{h.os_guess}]" if h.os_guess != "Unknown" else ""
            ports_tag = f"  {len(h.open_ports)} ports" if h.open_ports else ""
            local_tag = " (this machine)" if h.is_local else ""
            text.append(f"    {h.ip:<16}", style="dim")
            text.append(f"  {label}")
            if os_tag:
                text.append(f"  {os_tag}", style="cyan")
            if ports_tag:
                text.append(ports_tag, style="dim")
            text.append(f"{local_tag}\n", style="green bold" if h.is_local else "")
        if len(inv.network_hosts) > 8:
            text.append(f"    … and {len(inv.network_hosts) - 8} more\n", style="dim")

    return Panel(text, title="System Inventory", border_style="blue", expand=False)


def render_terminal(report: AssessmentReport) -> None:
    sys_info = report.system
    header = (
        f"[bold]SysPulse Security Assessment[/bold]  —  "
        f"[cyan]{sys_info.hostname}[/cyan]  —  "
        f"{sys_info.assessed_at.strftime('%Y-%m-%d %H:%M UTC')}"
    )
    console.print(Panel(header, border_style="blue"))
    console.print("  Overall Risk: ", end="")
    console.print(_tier_badge(report.score.tier, report.score.overall))
    console.print()

    console.print(Columns([
        _summary_panel(report),
        _critical_panel(report.score.ranked_matches),
        _inventory_panel(report),
    ]))
    console.print()

    console.print(_findings_table(report.score.ranked_matches))
    console.print()

    if report.compliance_results:
        console.print(_compliance_table(report.compliance_results))
        console.print()

    console.print(_remediation_panel(report.score.ranked_matches))
