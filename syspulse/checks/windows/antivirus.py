from __future__ import annotations

from datetime import datetime, timezone

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script

_STALE_DAYS = 3  # definitions older than this are considered stale


class AntivirusCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-AV-001",
        name="Antivirus Status",
        category="antivirus",
        platform="windows",
        requires_admin=False,
        tags=["cis-5", "nist-si-3"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_av_status.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_av_status.ps1", raw_output=data)
        findings: list[Finding] = []

        providers = data.get("providers", [])
        if not providers:
            findings.append(Finding(
                id=f"{self.meta.id}-NO-AV",
                check_id=self.meta.id,
                title="No Antivirus Provider Registered",
                description="Windows Security Center reports no registered antivirus product.",
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                remediation_steps=[
                    "Enable Windows Defender: Set-MpPreference -DisableRealtimeMonitoring $false",
                    "Install a third-party AV solution if Defender is not suitable",
                ],
                tags=["cis-5.1", "nist-si-3"],
            ))
        else:
            # Check definition age
            last_updated_str = data.get("signatures_last_updated")
            if last_updated_str:
                try:
                    last_updated = datetime.fromisoformat(last_updated_str.replace("Z", "+00:00"))
                    age_days = (datetime.now(timezone.utc) - last_updated).days
                    if age_days > _STALE_DAYS:
                        findings.append(Finding(
                            id=f"{self.meta.id}-STALE-DEFS",
                            check_id=self.meta.id,
                            title=f"Antivirus Definitions Are {age_days} Days Old",
                            description=(
                                f"AV definitions were last updated {age_days} days ago. "
                                f"Definitions older than {_STALE_DAYS} days may miss recent threats."
                            ),
                            severity=Severity.HIGH,
                            status=CheckStatus.WARNING,
                            platform="windows",
                            category=self.meta.category,
                            evidence=[evidence],
                            remediation_steps=[
                                "Update definitions: Update-MpSignature",
                                "Ensure Windows Update is reachable and the Defender service is running",
                            ],
                            tags=["cis-5.1", "nist-si-3"],
                        ))
                except (ValueError, TypeError):
                    pass

        if not findings:
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="Antivirus Present and Definitions Current",
                description=f"Registered providers: {', '.join(p.get('displayName','?') for p in providers)}",
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
        category="antivirus",
    )
