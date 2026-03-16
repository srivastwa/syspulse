from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.mfa import MFACheck
from syspulse.models.finding import CheckStatus, Severity


_AAD_WHFB_OK = {
    "azure_ad_joined": True,
    "whfb_enrolled": True,
    "local_accounts_no_password": [],
    "password_never_expires": [],
}

_AAD_NO_WHFB = {
    "azure_ad_joined": True,
    "whfb_enrolled": False,
    "local_accounts_no_password": [],
    "password_never_expires": [],
}

_NOT_AAD = {
    "azure_ad_joined": False,
    "whfb_enrolled": False,
    "local_accounts_no_password": [],
    "password_never_expires": [],
}

_NO_PASSWORD_ACCOUNT = {
    "azure_ad_joined": True,
    "whfb_enrolled": True,
    "local_accounts_no_password": ["testuser"],
    "password_never_expires": [],
}

_PWD_NEVER_EXPIRES = {
    "azure_ad_joined": True,
    "whfb_enrolled": True,
    "local_accounts_no_password": [],
    "password_never_expires": ["svcaccount"],
}


def test_aad_whfb_enrolled_passes():
    with patch("syspulse.checks.windows.mfa.run_powershell_script", return_value=_AAD_WHFB_OK):
        findings = MFACheck().run()
    assert all(f.status == CheckStatus.PASS for f in findings)


def test_aad_no_whfb_is_fail():
    with patch("syspulse.checks.windows.mfa.run_powershell_script", return_value=_AAD_NO_WHFB):
        findings = MFACheck().run()
    fails = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fails
    assert fails[0].severity == Severity.HIGH


def test_not_aad_joined_is_warning():
    with patch("syspulse.checks.windows.mfa.run_powershell_script", return_value=_NOT_AAD):
        findings = MFACheck().run()
    warns = [f for f in findings if f.status == CheckStatus.WARNING]
    assert warns


def test_no_password_account_is_critical():
    with patch("syspulse.checks.windows.mfa.run_powershell_script", return_value=_NO_PASSWORD_ACCOUNT):
        findings = MFACheck().run()
    crits = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crits
    assert "testuser" in crits[0].affected_resources


def test_pwd_never_expires_is_warning():
    with patch("syspulse.checks.windows.mfa.run_powershell_script", return_value=_PWD_NEVER_EXPIRES):
        findings = MFACheck().run()
    warns = [f for f in findings if f.status == CheckStatus.WARNING and "expires" in f.title.lower()]
    assert warns
    assert "svcaccount" in warns[0].affected_resources


def test_script_error():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.mfa.run_powershell_script",
               side_effect=SubprocessError("get_mfa_status.ps1", 1, "err")):
        findings = MFACheck().run()
    assert findings[0].status == CheckStatus.ERROR
