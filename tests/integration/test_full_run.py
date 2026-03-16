"""
Integration test: full dry-run produces a valid AssessmentReport.
"""
from __future__ import annotations

from syspulse.runner import run_assessment
from syspulse.models.report import AssessmentReport


def test_dry_run_returns_report():
    report = run_assessment(dry_run=True)
    assert isinstance(report, AssessmentReport)
    assert report.system.hostname
    assert report.score.overall == 0.0
    assert report.score.tier == "LOW"
    assert report.score.ranked_matches == []


def test_dry_run_json_serializable():
    import json
    report = run_assessment(dry_run=True)
    serialized = report.model_dump_json()
    parsed = json.loads(serialized)
    assert parsed["schema_version"] == "1.0"
    assert "system" in parsed
    assert "score" in parsed
