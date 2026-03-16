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

from syspulse.utils.logging import configure_logging

app = typer.Typer(
    name="syspulse",
    help="Cross-platform security assessment agent.",
    add_completion=False,
)


@app.command()
def scan(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Run without executing checks.")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Override HTML output path.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logging.")] = False,
) -> None:
    """Run a full security assessment — shows results on screen and saves an HTML report."""
    configure_logging(verbose)

    from syspulse.runner import run_assessment

    try:
        report = run_assessment(dry_run=dry_run)
    except Exception as exc:
        typer.echo(f"[ERROR] Assessment failed: {exc}", err=True)
        raise typer.Exit(code=1)

    # ── Terminal dashboard ──────────────────────────────────────────────────
    from syspulse.output.terminal import render_terminal
    render_terminal(report)

    # ── HTML report ─────────────────────────────────────────────────────────
    from syspulse.output.html_report import export_html
    if output is None:
        hostname = platform.node().split(".")[0].lower()
        date_str = datetime.now().strftime("%d%m%y")
        output = Path(f"eciso-syspulse-{hostname}-{date_str}.html")

    output.write_text(export_html(report), encoding="utf-8")
    typer.echo(f"\n  HTML report saved → {output}")
