from __future__ import annotations

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script

_STALE_DAYS = 30


class PatchingCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-PATCH-001",
        name="Windows Update / Patch Status",
        category="patching",
        platform="windows",
        requires_admin=False,
        tags=["cis-18.9.108", "nist-si-2"],
    )

    def run(self) -> list[Finding]:
        try:
            # WUA live search can take 60-120s on WSUS/corporate machines
            data = run_powershell_script("get_update_status.ps1", timeout=120)
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_update_status.ps1", raw_output=data)
        findings: list[Finding] = []

        pending = data.get("pending_updates", [])
        critical_pending = [u for u in pending if u.get("is_security", False)]
        days_since = data.get("days_since_last_install", 0) or 0
        reboot_required = data.get("reboot_required", False)
        search_timed_out = data.get("search_timed_out", False)

        if reboot_required and not critical_pending:
            findings.append(Finding(
                id=f"{self.meta.id}-REBOOT",
                check_id=self.meta.id,
                title="Reboot Required to Complete Pending Updates",
                description=(
                    "Windows Update has staged patches that require a reboot to complete. "
                    "The system is not fully patched until it is restarted."
                ),
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=["Restart the machine to finish applying pending updates."],
                tags=["cis-18.9.108", "nist-si-2"],
            ))

        if critical_pending:
            titles = [u.get("title", "Unknown") for u in critical_pending[:5]]
            findings.append(Finding(
                id=f"{self.meta.id}-CRITICAL-PENDING",
                check_id=self.meta.id,
                title=f"{len(critical_pending)} Critical/Security Update(s) Pending",
                description=(
                    f"The following security updates are pending installation: "
                    f"{'; '.join(titles)}"
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=[u.get("title", "?") for u in critical_pending],
                remediation_steps=[
                    "Install pending updates immediately via Windows Update Settings",
                    "Or run: Install-WindowsUpdate -AcceptAll -AutoReboot (requires PSWindowsUpdate module)",
                ],
                tags=["cis-18.9.108", "nist-si-2", "iso-a.12.6.1"],
            ))
        elif days_since > _STALE_DAYS:
            findings.append(Finding(
                id=f"{self.meta.id}-STALE",
                check_id=self.meta.id,
                title=f"System Not Patched in {days_since} Days",
                description=f"Last successful update installation was {days_since} days ago.",
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Review and install available Windows updates",
                    "Check Windows Update policy and service status",
                ],
                tags=["cis-18.9.108", "nist-si-2"],
            ))

        if not findings:
            note = " (live update search timed out — result based on cached data)" if search_timed_out else ""
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="System Patching Up to Date",
                description=(
                    f"No critical pending updates found. "
                    f"Last installed {days_since} days ago.{note}"
                ),
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
        category="patching",
    )
