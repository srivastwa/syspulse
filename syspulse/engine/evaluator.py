from __future__ import annotations

from syspulse.engine.rule_loader import Rule, load_all_rules
from syspulse.models.finding import Finding, Severity
from syspulse.models.risk import RuleMatch

_RULES: list[Rule] | None = None


def _get_rules() -> list[Rule]:
    global _RULES
    if _RULES is None:
        _RULES = load_all_rules()
    return _RULES


def _matches(finding: Finding, rule: Rule) -> bool:
    c = rule.condition
    if c.check_id is not None and finding.check_id != c.check_id:
        return False
    if c.check_id_prefix is not None and not finding.check_id.startswith(c.check_id_prefix):
        return False
    if c.category is not None and finding.category != c.category:
        return False
    if c.status is not None and finding.status.value != c.status:
        return False
    if c.tag is not None and c.tag not in finding.tags:
        return False
    return True


def evaluate_findings(findings: list[Finding]) -> list[RuleMatch]:
    """Match each finding against loaded rules and produce RuleMatch objects."""
    rules = _get_rules()
    matches: list[RuleMatch] = []

    for finding in findings:
        matched = False
        for rule in rules:
            if _matches(finding, rule):
                matches.append(RuleMatch(
                    finding=finding,
                    rule_id=rule.id,
                    base_score=rule.base_score,
                    final_score=rule.base_score,  # scorer will update this
                    severity=Severity(rule.severity.lower()),
                    cvss_vector=rule.cvss_vector,
                    remediation_steps=rule.remediation,
                    compliance_tags=rule.compliance_tags,
                ))
                matched = True
                break  # first matching rule wins

        if not matched:
            # No rule matched — use the finding's own severity to assign a default score
            score_map = {
                Severity.CRITICAL: 8.5,
                Severity.HIGH: 6.5,
                Severity.MEDIUM: 4.5,
                Severity.LOW: 2.0,
                Severity.INFO: 0.5,
            }
            matches.append(RuleMatch(
                finding=finding,
                rule_id="DEFAULT",
                base_score=score_map[finding.severity],
                final_score=score_map[finding.severity],
                severity=finding.severity,
                remediation_steps=finding.remediation_steps,
            ))

    return matches
