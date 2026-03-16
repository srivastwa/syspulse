from __future__ import annotations

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script


class MisconfigurationsCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-MISC-001",
        name="Common Windows Misconfigurations",
        category="misconfigurations",
        platform="windows",
        requires_admin=False,
        tags=["cis", "nist-cm-7"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_misconfigurations.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_misconfigurations.ps1", raw_output=data)
        findings: list[Finding] = []

        # SMBv1
        if data.get("smb1_enabled", False):
            findings.append(Finding(
                id="WIN-MISC-SMB1",
                check_id=self.meta.id,
                title="SMBv1 Protocol is Enabled",
                description=(
                    "SMBv1 is an obsolete protocol vulnerable to EternalBlue (MS17-010), "
                    "the exploit used by WannaCry and NotPetya ransomware."
                ),
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
                    "Remove feature: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                    "Verify: Get-SmbServerConfiguration | Select EnableSMB1Protocol",
                ],
                tags=["smb1", "cis-18.3.3", "nist-cm-7", "iso-a.12.6.1"],
            ))

        # Guest account
        if data.get("guest_enabled", False):
            findings.append(Finding(
                id="WIN-MISC-GUEST",
                check_id=self.meta.id,
                title="Guest Account is Enabled",
                description="The built-in Guest account is enabled, allowing unauthenticated local access.",
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Disable: Disable-LocalUser -Name Guest",
                ],
                tags=["guest-account", "cis-2.3.1.1", "nist-ac-2"],
            ))

        # AutoRun
        if data.get("autorun_enabled", False):
            findings.append(Finding(
                id="WIN-MISC-AUTORUN",
                check_id=self.meta.id,
                title="AutoRun/AutoPlay is Enabled",
                description=(
                    "AutoRun/AutoPlay is enabled. Malicious USB devices or media can execute "
                    "arbitrary code automatically when inserted."
                ),
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Disable via registry: Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255",
                    "Or via Group Policy: Administrative Templates > Windows Components > AutoPlay Policies",
                ],
                tags=["autorun", "cis-18.9.8.1", "nist-cm-7"],
            ))

        # RDP without NLA
        rdp_enabled = data.get("rdp_enabled", False)
        nla_enabled = data.get("nla_enabled", True)
        if rdp_enabled and not nla_enabled:
            findings.append(Finding(
                id="WIN-MISC-RDP-NO-NLA",
                check_id=self.meta.id,
                title="RDP Enabled Without Network Level Authentication",
                description=(
                    "Remote Desktop Protocol is enabled but Network Level Authentication (NLA) "
                    "is disabled. NLA prevents authentication before session establishment, "
                    "protecting against pre-auth exploits and credential spray attacks."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Enable NLA: Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
                    "Restrict RDP to specific IPs via Windows Firewall",
                ],
                tags=["rdp-nla-disabled", "cis-18.9.65.3.9.2", "nist-ac-17"],
            ))

        # Open shares
        open_shares = data.get("open_shares", [])
        if open_shares:
            share_names = ", ".join(open_shares)
            findings.append(Finding(
                id="WIN-MISC-OPEN-SHARES",
                check_id=self.meta.id,
                title=f"Open Network Share(s) Detected: {share_names}",
                description=(
                    f"The following non-administrative shares are accessible: {share_names}. "
                    "Open shares can expose sensitive data to lateral movement."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=open_shares,
                remediation_steps=[
                    "Review shares: Get-SmbShare | Where-Object { $_.Name -notlike '*$' }",
                    "Remove unnecessary shares: Remove-SmbShare -Name <name> -Force",
                    "Restrict share permissions to specific users/groups",
                ],
                tags=["open-shares", "cis-2.3.11.6", "nist-ac-3"],
            ))

        # Secure Boot
        if not data.get("secure_boot_enabled", True):
            findings.append(Finding(
                id="WIN-MISC-SECUREBOOT",
                check_id=self.meta.id,
                title="Secure Boot is Disabled",
                description=(
                    "Secure Boot is disabled. This allows unsigned bootloaders and bootkits "
                    "to execute before the OS loads, bypassing OS-level security."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Enable Secure Boot in UEFI/BIOS settings",
                    "Verify after reboot: Confirm-SecureBootUEFI",
                ],
                tags=["secure-boot-disabled", "cis-18.9.12", "nist-si-7"],
            ))

        # Weak password policy
        weak_pwd = data.get("weak_password_policy", {})
        if weak_pwd.get("min_length_insufficient") or weak_pwd.get("no_complexity") or weak_pwd.get("no_lockout"):
            issues = []
            if weak_pwd.get("min_length_insufficient"):
                issues.append(f"minimum length {weak_pwd.get('min_length', '?')} < 14")
            if weak_pwd.get("no_complexity"):
                issues.append("complexity not required")
            if weak_pwd.get("no_lockout"):
                issues.append("account lockout not configured")
            findings.append(Finding(
                id="WIN-MISC-WEAK-PWD",
                check_id=self.meta.id,
                title=f"Weak Password Policy: {'; '.join(issues)}",
                description=(
                    "Local password policy does not meet recommended security standards. "
                    f"Issues: {', '.join(issues)}."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Set minimum length: secedit /export /cfg c:\\policy.cfg && edit MinimumPasswordLength=14",
                    "Enable complexity: PasswordComplexity = 1",
                    "Set lockout: net accounts /lockoutthreshold:5 /lockoutduration:30",
                ],
                tags=["weak-password-policy", "cis-1.1.1", "cis-1.1.4", "nist-ia-5"],
            ))

        if not findings:
            findings.append(Finding(
                id="WIN-MISC-OK",
                check_id=self.meta.id,
                title="No Common Misconfigurations Detected",
                description="SMBv1, Guest, AutoRun, RDP, shares, Secure Boot, and password policy all pass.",
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
        category="misconfigurations",
    )
