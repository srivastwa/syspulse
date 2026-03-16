from __future__ import annotations

from syspulse.engine.scorer import compute_system_score, _score_to_tier
from syspulse.engine.evaluator import evaluate_findings
from syspulse.models.finding import CheckStatus, Finding, Severity


def _make_finding(sev: Severity, status: CheckStatus = CheckStatus.FAIL, check_id: str = "WIN-TEST-001") -> Finding:
    return Finding(
        id=f"{check_id}-{sev.value}",
        check_id=check_id,
        title=f"Test finding [{sev.value}]",
        description="Test",
        severity=sev,
        status=status,
        platform="windows",
        category="test",
    )


def test_score_tier_boundaries():
    assert _score_to_tier(8.0) == "CRITICAL"
    assert _score_to_tier(7.9) == "HIGH"
    assert _score_to_tier(6.0) == "HIGH"
    assert _score_to_tier(5.9) == "MEDIUM"
    assert _score_to_tier(4.0) == "MEDIUM"
    assert _score_to_tier(3.9) == "LOW"


def test_empty_findings_gives_zero(system_profile):
    matches = evaluate_findings([])
    score = compute_system_score(matches, system_profile)
    assert score.overall == 0.0
    assert score.tier == "LOW"


def test_critical_finding_scores_high(system_profile):
    findings = [_make_finding(Severity.CRITICAL)]
    matches = evaluate_findings(findings)
    score = compute_system_score(matches, system_profile)
    assert score.overall >= 6.0


def test_ranked_descending(system_profile):
    findings = [
        _make_finding(Severity.LOW, check_id="WIN-T-001"),
        _make_finding(Severity.CRITICAL, check_id="WIN-T-002"),
        _make_finding(Severity.MEDIUM, check_id="WIN-T-003"),
    ]
    matches = evaluate_findings(findings)
    score = compute_system_score(matches, system_profile)
    scores = [m.final_score for m in score.ranked_matches]
    assert scores == sorted(scores, reverse=True)
