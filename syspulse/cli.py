from __future__ import annotations

import sys
from enum import Enum
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


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    html = "html"


@app.command()
def scan(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Run without executing checks.")] = False,
    format: Annotated[OutputFormat, typer.Option("--format", "-f", help="Output format.")] = OutputFormat.terminal,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Write output to file.")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logging.")] = False,
) -> None:
    """Run a full security assessment on this machine."""
    configure_logging(verbose)

    from syspulse.runner import run_assessment

    try:
        report = run_assessment(dry_run=dry_run)
    except Exception as exc:
        typer.echo(f"[ERROR] Assessment failed: {exc}", err=True)
        raise typer.Exit(code=1)

    if format == OutputFormat.terminal:
        from syspulse.output.terminal import render_terminal
        render_terminal(report)

    elif format == OutputFormat.json:
        from syspulse.output.json_export import export_json
        content = export_json(report)
        if output:
            output.write_text(content, encoding="utf-8")
            typer.echo(f"Report written to {output}")
        else:
            typer.echo(content)

    elif format == OutputFormat.html:
        from syspulse.output.html_report import export_html
        content = export_html(report)
        if output:
            output.write_text(content, encoding="utf-8")
            typer.echo(f"Report written to {output}")
        else:
            typer.echo(content)
