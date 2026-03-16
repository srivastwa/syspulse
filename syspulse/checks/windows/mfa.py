from __future__ import annotations

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script


class MFACheck(CheckBase):
    meta = CheckMeta(
        id="WIN-MFA-001",
        name="MFA / Account Security Status",
        category="mfa",
        platform="windows",
        requires_admin=False,
        tags=["cis-16.3", "nist-ia-2"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_mfa_status.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_mfa_status.ps1", raw_output=data)
        findings: list[Finding] = []

        azure_ad_joined = data.get("azure_ad_joined", False)
        whfb_enrolled = data.get("whfb_enrolled", False)
        local_accounts_no_password = data.get("local_accounts_no_password", [])
        password_never_expires = data.get("password_never_expires", [])

        if not azure_ad_joined:
            findings.append(Finding(
                id=f"{self.meta.id}-NOT-AAD",
                check_id=self.meta.id,
                title="Device Not Azure AD Joined — Cloud MFA Unavailable",
                description=(
                    "This device is not joined to Azure Active Directory. "
                    "Azure AD-based MFA and Conditional Access policies cannot be enforced."
                ),
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Join device to Azure AD: dsregcmd /join",
                    "Or use hybrid Azure AD join if domain-joined",
                    "Enable Windows Hello for Business as local MFA",
                ],
                tags=["nist-ia-2", "iso-a.9.4.2"],
            ))
        elif not whfb_enrolled:
            findings.append(Finding(
                id=f"{self.meta.id}-NO-WHFB",
                check_id=self.meta.id,
                title="Windows Hello for Business Not Enrolled",
                description=(
                    "Device is Azure AD joined but Windows Hello for Business (phishing-resistant MFA) "
                    "is not enrolled for the current user."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Enroll Windows Hello: Settings > Accounts > Sign-in options",
                    "Enable WHFB via Intune or Group Policy",
                    "Configure Conditional Access to require WHFB or FIDO2",
                ],
                tags=["cis-16.3", "nist-ia-2", "iso-a.9.4.2"],
            ))

        if local_accounts_no_password:
            names = ", ".join(local_accounts_no_password)
            findings.append(Finding(
                id=f"{self.meta.id}-NO-PWD",
                check_id=self.meta.id,
                title=f"Local Account(s) Accept Blank Password: {names}",
                description=(
                    f"The following accounts accept login with an empty password: {names}. "
                    "This allows unauthenticated local access and is a critical risk."
                ),
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=local_accounts_no_password,
                remediation_steps=[
                    "Set password: net user <username> <password>",
                    "Or disable unused accounts: Disable-LocalUser -Name <username>",
                ],
                tags=["cis-16", "nist-ia-5"],
            ))

        if password_never_expires:
            names = ", ".join(password_never_expires)
            findings.append(Finding(
                id=f"{self.meta.id}-PWD-NEVER-EXPIRES",
                check_id=self.meta.id,
                title=f"Password Never Expires on Account(s): {names}",
                description="Passwords that never expire increase the risk from credential compromise.",
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=password_never_expires,
                remediation_steps=[
                    "Enable password expiration: Set-LocalUser -Name <user> -PasswordNeverExpires $false",
                    "Set maximum password age via Group Policy",
                ],
                tags=["cis-1.1", "nist-ia-5"],
            ))

        if not findings:
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="MFA Configured — Azure AD Joined with Windows Hello",
                description="Device is Azure AD joined and Windows Hello for Business is enrolled.",
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
        category="mfa",
    )
