from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.patching import PatchingCheck
from syspulse.models.finding import CheckStatus, Severity


_UP_TO_DATE = {"pending_updates": [], "pending_count": 0, "days_since_last_install": 5}

_CRITICAL_PENDING = {
    "pending_updates": [
        {"title": "2024-03 Cumulative Update for Windows 11", "is_security": True, "kb_ids": ["KB1234567"], "severity": "Critical"},
        {"title": "2024-02 Cumulative Update for Windows 11", "is_security": True, "kb_ids": ["KB7654321"], "severity": "Important"},
    ],
    "pending_count": 2,
    "days_since_last_install": 45,
}

_STALE_NO_CRITICAL = {
    "pending_updates": [
        {"title": "Optional driver update", "is_security": False, "kb_ids": [], "severity": "Low"},
    ],
    "pending_count": 1,
    "days_since_last_install": 35,
}


def test_up_to_date_passes():
    with patch("syspulse.checks.windows.patching.run_powershell_script", return_value=_UP_TO_DATE):
        findings = PatchingCheck().run()
    assert findings[0].status == CheckStatus.PASS


def test_critical_pending_is_high():
    with patch("syspulse.checks.windows.patching.run_powershell_script", return_value=_CRITICAL_PENDING):
        findings = PatchingCheck().run()
    fails = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fails
    assert fails[0].severity == Severity.HIGH
    assert "2" in fails[0].title


def test_stale_without_critical_is_warning():
    with patch("syspulse.checks.windows.patching.run_powershell_script", return_value=_STALE_NO_CRITICAL):
        findings = PatchingCheck().run()
    warns = [f for f in findings if f.status == CheckStatus.WARNING]
    assert warns
    assert warns[0].severity == Severity.MEDIUM


def test_script_error():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.patching.run_powershell_script",
               side_effect=SubprocessError("get_update_status.ps1", 1, "WUA unavailable")):
        findings = PatchingCheck().run()
    assert findings[0].status == CheckStatus.ERROR
