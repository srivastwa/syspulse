from __future__ import annotations

import json

from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import CheckStatus, Evidence, Finding, Severity
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script


class FirewallCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-FW-001",
        name="Windows Firewall Status",
        category="firewall",
        platform="windows",
        requires_admin=False,
        tags=["cis-9", "nist-sc-7"],
    )

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_firewall_profiles.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]

        evidence = Evidence(source="powershell:get_firewall_profiles.ps1", raw_output=data)
        findings: list[Finding] = []

        profiles = data.get("profiles", [])
        disabled = [p for p in profiles if not p.get("enabled", True)]

        if disabled:
            names = ", ".join(p["name"] for p in disabled)
            findings.append(Finding(
                id=f"{self.meta.id}-DISABLED",
                check_id=self.meta.id,
                title=f"Firewall disabled on profile(s): {names}",
                description=(
                    f"Windows Defender Firewall is disabled for the following profile(s): {names}. "
                    "This exposes the system to inbound network attacks."
                ),
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                platform="windows",
                category=self.meta.category,
                evidence=[evidence],
                affected_resources=[p["name"] for p in disabled],
                remediation_steps=[
                    "Enable all profiles: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                    "Verify: Get-NetFirewallProfile | Select Name, Enabled",
                ],
                tags=["cis-9.1.1", "cis-9.2.1", "cis-9.3.1", "nist-sc-7"],
            ))

        if not findings:
            findings.append(Finding(
                id=f"{self.meta.id}-OK",
                check_id=self.meta.id,
                title="Windows Firewall enabled on all profiles",
                description="Domain, Private, and Public profiles are all enabled.",
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
        category="firewall",
    )
