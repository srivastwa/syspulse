from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from syspulse.models.report import AssessmentReport

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def export_html(report: AssessmentReport) -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")
    return template.render(report=report)
