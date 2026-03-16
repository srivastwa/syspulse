from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.misconfigurations import MisconfigurationsCheck
from syspulse.models.finding import CheckStatus, Severity


_ALL_CLEAN = {
    "smb1_enabled": False,
    "guest_enabled": False,
    "autorun_enabled": False,
    "rdp_enabled": False,
    "nla_enabled": True,
    "open_shares": [],
    "secure_boot_enabled": True,
    "weak_password_policy": {
        "min_length": 14,
        "min_length_insufficient": False,
        "no_complexity": False,
        "no_lockout": False,
        "lockout_threshold": 5,
    },
}

_SMB1_ENABLED = {**_ALL_CLEAN, "smb1_enabled": True}
_GUEST_ENABLED = {**_ALL_CLEAN, "guest_enabled": True}
_AUTORUN_ENABLED = {**_ALL_CLEAN, "autorun_enabled": True}
_RDP_NO_NLA = {**_ALL_CLEAN, "rdp_enabled": True, "nla_enabled": False}
_OPEN_SHARES = {**_ALL_CLEAN, "open_shares": ["Public", "Shared"]}
_NO_SECURE_BOOT = {**_ALL_CLEAN, "secure_boot_enabled": False}
_WEAK_PWD = {
    **_ALL_CLEAN,
    "weak_password_policy": {
        "min_length": 6,
        "min_length_insufficient": True,
        "no_complexity": True,
        "no_lockout": True,
        "lockout_threshold": 0,
    },
}


def test_all_clean_passes():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_ALL_CLEAN):
        findings = MisconfigurationsCheck().run()
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.PASS


def test_smb1_is_critical():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_SMB1_ENABLED):
        findings = MisconfigurationsCheck().run()
    smb = [f for f in findings if "SMB" in f.title]
    assert smb
    assert smb[0].severity == Severity.CRITICAL


def test_guest_account_enabled():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_GUEST_ENABLED):
        findings = MisconfigurationsCheck().run()
    guest = [f for f in findings if "Guest" in f.title]
    assert guest
    assert guest[0].severity == Severity.HIGH


def test_rdp_without_nla():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_RDP_NO_NLA):
        findings = MisconfigurationsCheck().run()
    rdp = [f for f in findings if "RDP" in f.title or "NLA" in f.title]
    assert rdp


def test_open_shares_detected():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_OPEN_SHARES):
        findings = MisconfigurationsCheck().run()
    shares = [f for f in findings if "Share" in f.title]
    assert shares
    assert "Public" in shares[0].affected_resources


def test_secure_boot_disabled():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_NO_SECURE_BOOT):
        findings = MisconfigurationsCheck().run()
    sb = [f for f in findings if "Secure Boot" in f.title]
    assert sb


def test_weak_password_policy():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_WEAK_PWD):
        findings = MisconfigurationsCheck().run()
    pwd = [f for f in findings if "Password" in f.title or "password" in f.title.lower()]
    assert pwd


def test_autorun_enabled():
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script", return_value=_AUTORUN_ENABLED):
        findings = MisconfigurationsCheck().run()
    auto = [f for f in findings if "AutoRun" in f.title or "AutoPlay" in f.title]
    assert auto


def test_script_error():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.misconfigurations.run_powershell_script",
               side_effect=SubprocessError("get_misconfigurations.ps1", 1, "err")):
        findings = MisconfigurationsCheck().run()
    assert findings[0].status == CheckStatus.ERROR
