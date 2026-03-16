from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.privileges import PrivilegesCheck
from syspulse.models.finding import CheckStatus, Severity


_OK_DATA = {
    "local_admins": [
        {"name": "Administrator", "full_name": "BUILTIN\\Administrator", "enabled": False, "object_class": "User", "principal_source": "Local"},
        {"name": "JohnAdmin", "full_name": "PC\\JohnAdmin", "enabled": True, "object_class": "User", "principal_source": "Local"},
    ],
    "total_count": 2,
}

_BUILTIN_ENABLED = {
    "local_admins": [
        {"name": "administrator", "full_name": "BUILTIN\\Administrator", "enabled": True, "object_class": "User", "principal_source": "Local"},
    ],
    "total_count": 1,
}

_EXCESS_ADMINS = {
    "local_admins": [
        {"name": "administrator", "full_name": "BUILTIN\\Administrator", "enabled": False, "object_class": "User", "principal_source": "Local"},
        {"name": "User1", "full_name": "PC\\User1", "enabled": True, "object_class": "User", "principal_source": "Local"},
        {"name": "User2", "full_name": "PC\\User2", "enabled": True, "object_class": "User", "principal_source": "Local"},
        {"name": "User3", "full_name": "PC\\User3", "enabled": True, "object_class": "User", "principal_source": "Local"},
    ],
    "total_count": 4,
}


def test_single_admin_passes():
    with patch("syspulse.checks.windows.privileges.run_powershell_script", return_value=_OK_DATA):
        findings = PrivilegesCheck().run()
    assert all(f.status == CheckStatus.PASS for f in findings)


def test_builtin_admin_enabled_is_warning():
    with patch("syspulse.checks.windows.privileges.run_powershell_script", return_value=_BUILTIN_ENABLED):
        findings = PrivilegesCheck().run()
    warns = [f for f in findings if f.status == CheckStatus.WARNING]
    assert warns


def test_excess_admins_is_fail():
    with patch("syspulse.checks.windows.privileges.run_powershell_script", return_value=_EXCESS_ADMINS):
        findings = PrivilegesCheck().run()
    fails = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fails
    assert fails[0].severity == Severity.HIGH
    assert "3" in fails[0].title


def test_script_error():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.privileges.run_powershell_script",
               side_effect=SubprocessError("get_local_admins.ps1", 1, "Access denied")):
        findings = PrivilegesCheck().run()
    assert findings[0].status == CheckStatus.ERROR
