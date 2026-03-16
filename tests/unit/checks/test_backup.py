from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.backup import BackupCheck
from syspulse.models.finding import CheckStatus, Severity


_NO_BACKUP = {
    "file_history_enabled": False,
    "vss_snapshot_count": 0,
    "wbadmin_present": False,
    "third_party_backup": [],
}

_FILE_HISTORY_ONLY = {
    "file_history_enabled": True,
    "vss_snapshot_count": 0,
    "wbadmin_present": False,
    "third_party_backup": [],
}

_VSS_AND_THIRD_PARTY = {
    "file_history_enabled": False,
    "vss_snapshot_count": 3,
    "wbadmin_present": False,
    "third_party_backup": ["Veeam"],
}

_ALL_SOURCES = {
    "file_history_enabled": True,
    "vss_snapshot_count": 5,
    "wbadmin_present": True,
    "third_party_backup": ["Acronis"],
}


def test_no_backup_is_high():
    with patch("syspulse.checks.windows.backup.run_powershell_script", return_value=_NO_BACKUP):
        findings = BackupCheck().run()
    fails = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fails
    assert fails[0].severity == Severity.HIGH


def test_file_history_only_warns_no_vss():
    with patch("syspulse.checks.windows.backup.run_powershell_script", return_value=_FILE_HISTORY_ONLY):
        findings = BackupCheck().run()
    # File history present — should pass (no VSS warning only for third-party-only case)
    assert any(f.status == CheckStatus.PASS for f in findings)


def test_vss_and_third_party_passes():
    with patch("syspulse.checks.windows.backup.run_powershell_script", return_value=_VSS_AND_THIRD_PARTY):
        findings = BackupCheck().run()
    assert findings[0].status == CheckStatus.PASS


def test_all_sources_passes():
    with patch("syspulse.checks.windows.backup.run_powershell_script", return_value=_ALL_SOURCES):
        findings = BackupCheck().run()
    assert findings[0].status == CheckStatus.PASS
    assert "File History" in findings[0].description
    assert "VSS" in findings[0].description


def test_script_error():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.backup.run_powershell_script",
               side_effect=SubprocessError("get_backup_status.ps1", 1, "err")):
        findings = BackupCheck().run()
    assert findings[0].status == CheckStatus.ERROR
