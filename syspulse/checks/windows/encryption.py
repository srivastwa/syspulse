from __future__ import annotations

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script


class EncryptionCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-ENC-001",
        name="BitLocker Encryption Status",
        category="encryption",
        platform="windows",
        requires_admin=False,
        tags=["cis-18.9.11", "nist-sc-28"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_bitlocker_status.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_bitlocker_status.ps1", raw_output=data)
        findings: list[Finding] = []
        volumes = data.get("volumes", [])

        unencrypted = [v for v in volumes if not v.get("protection_on", False)]
        if unencrypted:
            for vol in unencrypted:
                drive = vol.get("mount_point", "Unknown")
                findings.append(Finding(
                    id=f"{self.meta.id}-{drive.replace(':', '').replace('\\', '')}",
                    check_id=self.meta.id,
                    title=f"BitLocker Not Enabled on {drive}",
                    description=(
                        f"Drive {drive} does not have BitLocker protection enabled. "
                        "Unencrypted drives expose data if the device is lost or stolen."
                    ),
                    severity=Severity.CRITICAL,
                    status=CheckStatus.FAIL,
                    platform="windows",
                    category=self.meta.category,
                    evidence=[evidence],
                    affected_resources=[drive],
                    remediation_steps=[
                        f"Enable BitLocker: manage-bde -on {drive} -RecoveryPassword",
                        "Store recovery key in Azure AD or Active Directory",
                        "Verify: manage-bde -status",
                    ],
                    tags=["cis-18.9.11.1.1", "nist-sc-28", "iso-a.10.1.1"],
                ))

        if not findings:
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="BitLocker Enabled on All Volumes",
                description=f"All {len(volumes)} volume(s) have BitLocker protection active.",
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
        category="encryption",
    )
