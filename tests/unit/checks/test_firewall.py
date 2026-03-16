from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.firewall import FirewallCheck
from syspulse.models.finding import CheckStatus, Severity


def test_firewall_all_enabled(firewall_ok_data):
    with patch("syspulse.checks.windows.firewall.run_powershell_script", return_value=firewall_ok_data):
        findings = FirewallCheck().run()
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.PASS


def test_firewall_some_disabled(firewall_fail_data):
    with patch("syspulse.checks.windows.firewall.run_powershell_script", return_value=firewall_fail_data):
        findings = FirewallCheck().run()
    fail = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fail
    assert fail[0].severity == Severity.HIGH
    assert "Domain" in fail[0].affected_resources
    assert "Public" in fail[0].affected_resources


def test_firewall_script_error():
    from syspulse.utils.subprocess_runner import SubprocessError
    with patch("syspulse.checks.windows.firewall.run_powershell_script",
               side_effect=SubprocessError("get_firewall_profiles.ps1", 1, "Access denied")):
        findings = FirewallCheck().run()
    assert findings[0].status == CheckStatus.ERROR
