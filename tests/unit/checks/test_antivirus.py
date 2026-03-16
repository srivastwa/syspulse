from __future__ import annotations

from unittest.mock import patch

from syspulse.checks.windows.antivirus import AntivirusCheck
from syspulse.models.finding import CheckStatus, Severity


def test_av_present_and_current(av_ok_data):
    with patch("syspulse.checks.windows.antivirus.run_powershell_script", return_value=av_ok_data):
        findings = AntivirusCheck().run()
    assert len(findings) == 1
    assert findings[0].status == CheckStatus.PASS


def test_av_no_provider(av_no_provider_data):
    with patch("syspulse.checks.windows.antivirus.run_powershell_script", return_value=av_no_provider_data):
        findings = AntivirusCheck().run()
    fail = [f for f in findings if f.status == CheckStatus.FAIL]
    assert fail
    assert fail[0].severity == Severity.CRITICAL


def test_av_stale_definitions(av_ok_data):
    from datetime import datetime, timedelta, timezone
    stale_data = dict(av_ok_data)
    stale_date = datetime.now(timezone.utc) - timedelta(days=10)
    stale_data["signatures_last_updated"] = stale_date.isoformat()
    with patch("syspulse.checks.windows.antivirus.run_powershell_script", return_value=stale_data):
        findings = AntivirusCheck().run()
    warn = [f for f in findings if f.status == CheckStatus.WARNING]
    assert warn
    assert "10" in warn[0].title or "Days" in warn[0].title
