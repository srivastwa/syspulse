from __future__ import annotations

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script


class BackupCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-BACKUP-001",
        name="Backup Configuration",
        category="backup",
        platform="windows",
        requires_admin=False,
        tags=["nist-cp-9", "iso-a.12.3.1"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_backup_status.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_backup_status.ps1", raw_output=data)
        findings: list[Finding] = []

        file_history = data.get("file_history_enabled", False)
        vss_snapshots = data.get("vss_snapshot_count", 0) or 0
        wbadmin_present = data.get("wbadmin_present", False)
        third_party = data.get("third_party_backup", [])

        has_backup = file_history or vss_snapshots > 0 or wbadmin_present or len(third_party) > 0

        if not has_backup:
            findings.append(Finding(
                id=f"{self.meta.id}-NO-BACKUP",
                check_id=self.meta.id,
                title="No Backup Solution Detected",
                description=(
                    "No backup solution (File History, VSS, Windows Backup, or third-party) "
                    "was detected. Data loss is unrecoverable in case of ransomware or hardware failure."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Enable File History: Settings > Update & Security > Backup",
                    "Enable VSS: vssadmin create shadow /for=C:",
                    "Consider a third-party backup solution with offsite storage",
                ],
                tags=["nist-cp-9", "iso-a.12.3.1"],
            ))
        elif vss_snapshots == 0 and not file_history:
            findings.append(Finding(
                id=f"{self.meta.id}-NO-VSS",
                check_id=self.meta.id,
                title="Third-Party Backup Present but No VSS/File History",
                description="VSS shadow copies and File History are not configured alongside the third-party backup.",
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Enable VSS for rapid local recovery: vssadmin create shadow /for=C:",
                    "Consider enabling File History as an additional layer",
                ],
                tags=["nist-cp-9"],
            ))

        if not findings:
            backup_sources = []
            if file_history:
                backup_sources.append("File History")
            if vss_snapshots:
                backup_sources.append(f"VSS ({vss_snapshots} snapshot(s))")
            if wbadmin_present:
                backup_sources.append("Windows Backup")
            backup_sources.extend(third_party)
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="Backup Solution Detected",
                description=f"Active backup sources: {', '.join(backup_sources)}",
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
        category="backup",
    )
