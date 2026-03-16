from __future__ import annotations

import platform
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from typing import Annotated
except ImportError:
    from typing_extensions import Annotated  # type: ignore

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from syspulse.utils.logging import configure_logging

app = typer.Typer(
    name="syspulse",
    help="Cross-platform security assessment agent.",
    add_completion=False,
)

console = Console()


def _show_menu() -> str:
    """Show startup menu and return the user's choice ('1' or '2')."""
    console.print()
    console.print(Panel(
        Text.from_markup(
            "  [bold cyan]1[/bold cyan]  Generate Report\n"
            "  [bold cyan]2[/bold cyan]  Generate Report [bold]and[/bold] Submit to [bold green]eCISO[/bold green]"
        ),
        title="[bold white]SysPulse — Select Action[/bold white]",
        border_style="cyan",
        expand=False,
        padding=(1, 4),
    ))
    return Prompt.ask(
        "  [cyan]Choice[/cyan]",
        choices=["1", "2"],
        default="1",
    )


def _submit_to_eciso(report_json: str) -> None:
    """POST the JSON report to the eCISO server."""
    import urllib.request
    import urllib.error
    from syspulse.config import settings

    url = f"{settings.eciso_server_url.rstrip('/')}/api/reports"
    data = report_json.encode("utf-8")

    with console.status(
        f"  [bold blue]Submitting report to eCISO[/bold blue] [dim]{url}[/dim]…",
        spinner="dots",
    ):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
            console.print(f"  [green]✓[/green] Report submitted successfully (HTTP {status})")
        except urllib.error.URLError as exc:
            console.print(f"  [red]✗[/red] Submission failed: {exc.reason}")
            console.print(
                "  [dim]Is the eCISO server running? Start it with:[/dim] "
                "[cyan]cd server && uvicorn main:app --reload[/cyan]"
            )


@app.command()
def scan(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Run without executing checks.")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Override HTML output path.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logging.")] = False,
    no_menu: Annotated[bool, typer.Option("--no-menu", help="Skip interactive menu (generate report only).")] = False,
) -> None:
    """Run a full security assessment — shows results on screen and saves an HTML report."""
    configure_logging(verbose)

    # ── Startup menu ────────────────────────────────────────────────────────
    submit = False
    if not no_menu and not dry_run:
        choice = _show_menu()
        submit = (choice == "2")
    console.print()

    # ── Run assessment ───────────────────────────────────────────────────────
    from syspulse.runner import run_assessment
    try:
        report = run_assessment(dry_run=dry_run)
    except Exception as exc:
        typer.echo(f"[ERROR] Assessment failed: {exc}", err=True)
        raise typer.Exit(code=1)

    # ── Terminal dashboard ───────────────────────────────────────────────────
    from syspulse.output.terminal import render_terminal
    render_terminal(report)

    # ── HTML report ──────────────────────────────────────────────────────────
    from syspulse.output.html_report import export_html
    if output is None:
        hostname = platform.node().split(".")[0].lower()
        date_str = datetime.now().strftime("%d%m%y")
        output = Path(f"eciso-syspulse-{hostname}-{date_str}.html")

    output.write_text(export_html(report), encoding="utf-8")
    console.print(f"\n  [dim]HTML report saved →[/dim] [cyan]{output}[/cyan]")

    # ── Submit to eCISO ───────────────────────────────────────────────────────
    if submit:
        from syspulse.output.json_export import export_json
        _submit_to_eciso(export_json(report))
