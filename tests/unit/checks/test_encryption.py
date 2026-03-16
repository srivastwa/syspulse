from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.encryption import EncryptionCheck
from syspulse.models.finding import CheckStatus, Severity


_OK_DATA = {
    "volumes": [
        {"mount_point": "C:", "protection_on": True, "protection_status": "On", "encryption_percentage": 100, "key_protectors": ["RecoveryPassword", "Tpm"]},
        {"mount_point": "D:", "protection_on": True, "protection_status": "On", "encryption_percentage": 100, "key_protectors": ["RecoveryPassword"]},
    ]
}

_FAIL_DATA = {
    "volumes": [
        {"mount_point": "C:", "protection_on": False, "protection_status": "Off", "encryption_percentage": 0, "key_protectors": []},
        {"mount_point": "D:", "protection_on": True, "protection_status": "On", "encryption_percentage": 100, "key_protectors": ["RecoveryPassword"]},
    ]
}

_NO_VOLUMES = {"volumes": []}


def test_all_encrypted():
    with patch("syspulse.checks.windows.encryption.run_powershell_script", return_value=_OK_DATA):
        findings = EncryptionCheck().run()
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.PASS


def test_unencrypted_drive_produces_critical():
    with patch("syspulse.checks.windows.encryption.run_powershell_script", return_value=_FAIL_DATA):
        findings = EncryptionCheck().run()
    fails = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fails
    assert fails[0].severity == Severity.CRITICAL
    assert "C:" in fails[0].affected_resources
    assert "D:" not in fails[0].affected_resources


def test_no_volumes_no_crash():
    with patch("syspulse.checks.windows.encryption.run_powershell_script", return_value=_NO_VOLUMES):
        findings = EncryptionCheck().run()
    assert findings[0].status == CheckStatus.PASS


def test_script_error_returns_error_finding():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.encryption.run_powershell_script",
               side_effect=SubprocessError("get_bitlocker_status.ps1", 1, "err")):
        findings = EncryptionCheck().run()
    assert findings[0].status == CheckStatus.ERROR
