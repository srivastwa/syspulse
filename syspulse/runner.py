from __future__ import annotations

import getpass
import socket

from syspulse.checks.registry import discover_checks
from syspulse.models.finding import CheckStatus, Finding
from syspulse.models.report import AssessmentReport, SystemProfile
from syspulse.models.risk import SystemScore
from syspulse.utils.logging import get_logger
from syspulse.utils.platform_detect import Platform, current_platform, is_admin, system_info

log = get_logger(__name__)


def _build_system_profile(platform: Platform, admin: bool) -> SystemProfile:
    info = system_info()
    # Azure AD join detection is Windows-specific; stub False on other platforms
    azure_ad = False
    domain_joined = False
    if platform == Platform.WINDOWS:
        try:
            import subprocess, json
            r = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True, text=True, timeout=10
            )
            for line in r.stdout.splitlines():
                if "AzureAdJoined" in line and "YES" in line:
                    azure_ad = True
                if "DomainJoined" in line and "YES" in line:
                    domain_joined = True
        except Exception:
            pass

    return SystemProfile(
        hostname=info["hostname"] or socket.gethostname(),
        os_name=info["os_name"],
        os_version=info["os_version"],
        os_build=info["os_build"],
        architecture=info["architecture"],
        domain_joined=domain_joined,
        azure_ad_joined=azure_ad,
        current_user=getpass.getuser(),
        is_admin=admin,
    )


def run_assessment(dry_run: bool = False) -> AssessmentReport:
    """
    Discover and run all applicable checks for the current platform,
    score findings through the rule engine, and return an AssessmentReport.
    """
    platform = current_platform()
    admin = is_admin()

    log.info("starting assessment", platform=platform.value, admin=admin, dry_run=dry_run)

    system_profile = _build_system_profile(platform, admin)

    findings: list[Finding] = []

    if not dry_run:
        check_classes = discover_checks(platform.value)
        log.info("discovered checks", count=len(check_classes))

        for check_cls in check_classes:
            check = check_cls()
            if not check.is_applicable(platform.value, admin):
                log.debug("skipping check", id=check.meta.id, reason="not applicable")
                continue
            try:
                results = check.run()
                findings.extend(results)
                log.debug("check complete", id=check.meta.id, findings=len(results))
            except Exception as exc:
                log.warning("check failed", id=check.meta.id, error=str(exc))
                # Emit an ERROR finding so the failure is visible in output
                findings.append(Finding(
                    id=f"{check.meta.id}-ERROR",
                    check_id=check.meta.id,
                    title=f"Check failed: {check.meta.name}",
                    description=str(exc),
                    severity=__import__("syspulse.models.finding", fromlist=["Severity"]).Severity.INFO,
                    status=CheckStatus.ERROR,
                    platform=platform.value,
                    category=check.meta.category,
                ))

    # Score findings through the rule engine
    from syspulse.engine.evaluator import evaluate_findings
    from syspulse.engine.scorer import compute_system_score

    matches = evaluate_findings(findings)
    system_score = compute_system_score(matches, system_profile)

    return AssessmentReport(
        system=system_profile,
        score=system_score,
    )
