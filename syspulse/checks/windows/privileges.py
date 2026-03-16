from __future__ import annotations

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script

# More than this many local admins (excluding well-known built-ins) is suspicious
_ADMIN_COUNT_THRESHOLD = 2


class PrivilegesCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-PRIV-001",
        name="Local Privilege / Admin Accounts",
        category="privileges",
        platform="windows",
        requires_admin=False,
        tags=["cis-2.2", "nist-ac-6"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_local_admins.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_local_admins.ps1", raw_output=data)
        findings: list[Finding] = []

        admins = data.get("local_admins", [])
        # Filter out well-known disabled built-in accounts
        active_admins = [a for a in admins if a.get("enabled", True)]
        builtin_admin_enabled = any(
            a.get("name", "").lower() == "administrator" and a.get("enabled", False)
            for a in admins
        )

        if builtin_admin_enabled:
            findings.append(Finding(
                id=f"{self.meta.id}-BUILTIN-ADMIN",
                check_id=self.meta.id,
                title="Built-in Administrator Account is Enabled",
                description=(
                    "The built-in Administrator account is enabled. This is a common attack target "
                    "as its RID (500) is predictable and it cannot be locked out by default."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=["Administrator"],
                remediation_steps=[
                    "Disable: Disable-LocalUser -Name Administrator",
                    "Use named admin accounts with MFA instead",
                ],
                tags=["cis-2.2.21", "nist-ac-6", "iso-a.9.2.3"],
            ))

        non_builtin = [
            a for a in active_admins
            if a.get("name", "").lower() not in ("administrator", "domain admins")
        ]
        if len(non_builtin) > _ADMIN_COUNT_THRESHOLD:
            names = ", ".join(a.get("name", "?") for a in non_builtin)
            findings.append(Finding(
                id=f"{self.meta.id}-EXCESS-ADMINS",
                check_id=self.meta.id,
                title=f"{len(non_builtin)} Non-Standard Local Admin Account(s) Found",
                description=(
                    f"The following accounts have local administrator privileges: {names}. "
                    f"More than {_ADMIN_COUNT_THRESHOLD} non-built-in admin accounts violates least-privilege."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=[a.get("name", "?") for a in non_builtin],
                remediation_steps=[
                    "Review local admins: Get-LocalGroupMember -Group Administrators",
                    "Remove unnecessary: Remove-LocalGroupMember -Group Administrators -Member <user>",
                    "Apply least-privilege — regular users should not be local admins",
                ],
                tags=["cis-2.2.21", "nist-ac-6", "iso-a.9.2.3"],
            ))

        if not findings:
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="Local Admin Accounts Within Acceptable Threshold",
                description=f"{len(active_admins)} active admin account(s) found, within policy.",
                severity=Severity.INFO,
                status=CheckStatus.PASS,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
            ))

        return findings


def _error_finding(check_id: str, msg: str) -> Finding:
    return Finding(
        id=f"{check_id}-ERROR",
        check_id=check_id,
        title="Check execution failed",
        description=msg,
        severity=Severity.INFO,
        status=CheckStatus.ERROR,
        platform="windows",
        category="privileges",
    )
