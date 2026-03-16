from __future__ import annotations

from syspulse.compliance.mapper import map_compliance
from syspulse.engine.evaluator import evaluate_findings
from syspulse.engine.scorer import compute_system_score
from syspulse.models.finding import CheckStatus, Finding, Severity


def _make_finding(check_id: str, status: CheckStatus, tags: list[str], sev: Severity = Severity.HIGH) -> Finding:
    return Finding(
        id=f"{check_id}-{status.value}",
        check_id=check_id,
        title=f"Test [{check_id}]",
        description="test",
        severity=sev,
        status=status,
        platform="windows",
        category="test",
        tags=tags,
    )


def test_map_compliance_returns_all_frameworks():
    results = map_compliance([])
    # Should return one result per framework JSON file
    names = {r.framework for r in results}
    assert any("CIS" in n for n in names)
    assert any("NIST" in n for n in names)
    assert any("ISO" in n for n in names)


def test_failing_finding_marks_control_fail(system_profile):
    # A finding that is FAIL and has a compliance tag should mark that control fail
    findings = [_make_finding("WIN-FW-001", CheckStatus.FAIL, [], sev=Severity.HIGH)]
    matches = evaluate_findings(findings)
    # Inject a compliance tag manually into the match
    match = matches[0]
    match = match.model_copy(update={"compliance_tags": ["CIS-9.1.1"]})
    results = map_compliance([match])

    cis = next(r for r in results if "CIS" in r.framework)
    fw_control = next((d for d in cis.details if d.control.id == "CIS-9.1.1"), None)
    assert fw_control is not None
    assert fw_control.status == "fail"
    assert cis.failing >= 1


def test_passing_finding_marks_control_pass(system_profile):
    findings = [_make_finding("WIN-FW-001", CheckStatus.PASS, [], sev=Severity.INFO)]
    matches = evaluate_findings(findings)
    match = matches[0].model_copy(update={"compliance_tags": ["CIS-9.1.1"]})
    results = map_compliance([match])

    cis = next(r for r in results if "CIS" in r.framework)
    fw_control = next((d for d in cis.details if d.control.id == "CIS-9.1.1"), None)
    assert fw_control is not None
    assert fw_control.status == "pass"


def test_uncovered_control_is_not_covered():
    results = map_compliance([])
    for r in results:
        assert all(d.status == "not_covered" for d in r.details)
        assert r.passing == 0
        assert r.failing == 0
        assert r.not_covered == r.total_controls


def test_pass_rate_calculation(system_profile):
    # Two controls in CIS: one fail, one pass
    m_fail = evaluate_findings([
        _make_finding("WIN-A", CheckStatus.FAIL, [], sev=Severity.HIGH)
    ])[0].model_copy(update={"compliance_tags": ["CIS-9.1.1"]})
    m_pass = evaluate_findings([
        _make_finding("WIN-B", CheckStatus.PASS, [], sev=Severity.INFO)
    ])[0].model_copy(update={"compliance_tags": ["CIS-9.2.1"]})

    results = map_compliance([m_fail, m_pass])
    cis = next(r for r in results if "CIS" in r.framework)
    assert cis.passing == 1
    assert cis.failing == 1
    assert cis.pass_rate == 50.0
