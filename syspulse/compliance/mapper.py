from __future__ import annotations

from syspulse.compliance.loader import FrameworkDefinition, load_all_frameworks
from syspulse.models.compliance import ControlResult, MappingResult
from syspulse.models.finding import CheckStatus
from syspulse.models.risk import RuleMatch


def map_compliance(matches: list[RuleMatch]) -> list[MappingResult]:
    """
    Map a scored list of RuleMatches against all loaded compliance frameworks.

    A control is:
    - "fail"        — its ID appears in compliance_tags of a FAIL or WARNING match
    - "pass"        — its ID appears in compliance_tags of a PASS match (and never in a fail)
    - "not_covered" — its ID does not appear in any match's compliance_tags
    """
    frameworks = load_all_frameworks()

    # Build sets of control IDs from failing/passing matches
    failing_tags: set[str] = set()
    passing_tags: set[str] = set()

    for m in matches:
        status = m.finding.status
        for tag in m.compliance_tags:
            if status in (CheckStatus.FAIL, CheckStatus.WARNING):
                failing_tags.add(tag)
            elif status == CheckStatus.PASS:
                passing_tags.add(tag)

    # Build a map from control ID → list of finding IDs that touch it
    tag_to_findings: dict[str, list[str]] = {}
    for m in matches:
        for tag in m.compliance_tags:
            tag_to_findings.setdefault(tag, []).append(m.finding.id)

    results: list[MappingResult] = []
    for fw in frameworks:
        details: list[ControlResult] = []
        n_pass = n_fail = n_nc = 0

        for control in fw.controls:
            cid = control.id
            finding_ids = tag_to_findings.get(cid, [])

            if cid in failing_tags:
                status = "fail"
                n_fail += 1
            elif cid in passing_tags:
                status = "pass"
                n_pass += 1
            else:
                status = "not_covered"
                n_nc += 1

            details.append(ControlResult(
                control=control,
                status=status,
                matched_finding_ids=finding_ids,
            ))

        covered = n_pass + n_fail
        pass_rate = round((n_pass / covered * 100), 1) if covered > 0 else 0.0

        results.append(MappingResult(
            framework=fw.framework,
            version=fw.version,
            total_controls=len(fw.controls),
            passing=n_pass,
            failing=n_fail,
            not_covered=n_nc,
            pass_rate=pass_rate,
            details=details,
        ))

    return results
