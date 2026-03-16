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

        def _vol_display(vol: dict) -> str:
            drive = vol.get("mount_point", "Unknown")
            label = vol.get("volume_label")
            return f"{drive} ({label})" if label else drive

        for vol in volumes:
            drive = vol.get("mount_point", "Unknown")
            drive_slug = drive.replace(":", "").replace("\\", "")
            display = _vol_display(vol)
            pct = vol.get("encryption_percentage", 0) or 0
            status_str = vol.get("volume_status", "")
            protection_on = vol.get("protection_on", False)

            if not protection_on:
                if pct > 0 and pct < 100:
                    # Encryption started but not finished
                    title = f"BitLocker Encryption In Progress on {display} ({pct}%)"
                    description = (
                        f"Drive {display} has BitLocker enabled but encryption is only {pct}% complete "
                        f"(VolumeStatus: {status_str}). Data is not fully protected until encryption finishes."
                    )
                    severity = Severity.HIGH
                elif "Suspended" in status_str:
                    title = f"BitLocker Protection Suspended on {display}"
                    description = (
                        f"BitLocker protection on {display} is suspended (VolumeStatus: {status_str}). "
                        "The drive is accessible without the recovery key while suspended."
                    )
                    severity = Severity.HIGH
                else:
                    title = f"BitLocker Not Enabled on {display}"
                    description = (
                        f"Drive {display} does not have BitLocker protection enabled "
                        f"(VolumeStatus: {status_str or 'FullyDecrypted'}). "
                        "Unencrypted drives expose all data if the device is lost or stolen."
                    )
                    severity = Severity.CRITICAL

                findings.append(Finding(
                    id=f"{self.meta.id}-{drive_slug}",
                    check_id=self.meta.id,
                    title=title,
                    description=description,
                    severity=severity,
                    status=CheckStatus.FAIL,
                    platform="windows",
                    category=self.meta.category,
                    evidence=[evidence],
                    affected_resources=[display],
                    remediation_steps=[
                        f"Enable BitLocker: manage-bde -on {drive} -RecoveryPassword",
                        "Store recovery key in Azure AD or Active Directory",
                        "Verify encryption status: manage-bde -status",
                    ],
                    tags=["cis-18.9.11.1.1", "nist-sc-28", "iso-a.10.1.1"],
                ))

        if not findings:
            vol_names = ", ".join(_vol_display(v) for v in volumes)
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title=f"BitLocker Fully Enabled on All {len(volumes)} Volume(s)",
                description=f"All volumes are fully encrypted with BitLocker protection active: {vol_names}.",
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
