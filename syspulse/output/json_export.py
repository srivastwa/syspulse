from __future__ import annotations

from syspulse.models.report import AssessmentReport


def export_json(report: AssessmentReport, indent: int = 2) -> str:
    return report.model_dump_json(indent=indent)
