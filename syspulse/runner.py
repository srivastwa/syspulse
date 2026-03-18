from __future__ import annotations

import getpass
import socket

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from syspulse.checks.registry import discover_checks
from syspulse.models.finding import CheckStatus, Finding, Severity
from syspulse.models.report import AssessmentReport, SystemProfile
from syspulse.utils.logging import get_logger
from syspulse.utils.platform_detect import Platform, current_platform, is_admin, system_info

log = get_logger(__name__)
console = Console()


def _build_system_profile(platform: Platform, admin: bool) -> SystemProfile:
    info = system_info()
    azure_ad = False
    domain_joined = False
    if platform == Platform.WINDOWS:
        try:
            import subprocess
            r = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True, text=True, timeout=10,
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
    Discover and run all applicable checks with a live progress bar,
    score findings through the rule engine, and return an AssessmentReport.
    """
    platform = current_platform()
    admin = is_admin()

    log.info("starting assessment", platform=platform.value, admin=admin, dry_run=dry_run)

    system_profile = _build_system_profile(platform, admin)
    findings: list[Finding] = []

    if not dry_run:
        check_classes = discover_checks(platform.value)
        applicable = [
            cls for cls in check_classes
            if cls().is_applicable(platform.value, admin)
        ]

        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]SysPulse[/bold blue] {task.description}"),
            BarColumn(bar_width=36),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

        with progress:
            task_id = progress.add_task(
                "Running security checks…",
                total=len(applicable),
            )

            for cls in applicable:
                check = cls()
                progress.update(
                    task_id,
                    description=f"[dim]{check.meta.name}[/dim]",
                )
                try:
                    results = check.run()
                    findings.extend(results)
                    log.debug("check complete", id=check.meta.id, findings=len(results))
                except Exception as exc:
                    log.warning("check failed", id=check.meta.id, error=str(exc))
                    findings.append(Finding(
                        id=f"{check.meta.id}-ERROR",
                        check_id=check.meta.id,
                        title=f"Check failed: {check.meta.name}",
                        description=str(exc),
                        severity=Severity.INFO,
                        status=CheckStatus.ERROR,
                        platform=platform.value,
                        category=check.meta.category,
                    ))
                finally:
                    progress.advance(task_id)

            progress.update(task_id, description="[green]All checks complete[/green]")

    # ── Score ───────────────────────────────────────────────────────────────
    with console.status("[bold blue]SysPulse[/bold blue]  Scoring findings…", spinner="dots"):
        from syspulse.engine.evaluator import evaluate_findings
        from syspulse.engine.scorer import compute_system_score
        matches = evaluate_findings(findings)
        system_score = compute_system_score(matches, system_profile)

    # ── Compliance mapping ──────────────────────────────────────────────────
    with console.status("[bold blue]SysPulse[/bold blue]  Mapping compliance frameworks…", spinner="dots"):
        from syspulse.compliance.mapper import map_compliance
        compliance_results = map_compliance(system_score.ranked_matches)

    # ── Inventory collection ────────────────────────────────────────────────
    inventory = None
    if not dry_run and platform == Platform.WINDOWS:
        with console.status("[bold blue]SysPulse[/bold blue]  Collecting system inventory…", spinner="dots"):
            from syspulse.inventory.collector import collect_inventory
            inventory = collect_inventory()

        with console.status(
            "[bold blue]SysPulse[/bold blue]  Scanning local network (this may take ~30s)…",
            spinner="dots",
        ):
            from syspulse.inventory.collector import collect_network_scan
            collect_network_scan(inventory)

    console.print()

    return AssessmentReport(
        system=system_profile,
        score=system_score,
        compliance_results=compliance_results,
        inventory=inventory,
    )
