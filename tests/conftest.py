"""
Shared pytest fixtures.

Windows check tests mock `run_powershell_script` so they run on any platform.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def firewall_ok_data():
    return {
        "profiles": [
            {"name": "Domain", "enabled": True, "default_inbound": "Block", "default_outbound": "Allow"},
            {"name": "Private", "enabled": True, "default_inbound": "Block", "default_outbound": "Allow"},
            {"name": "Public", "enabled": True, "default_inbound": "Block", "default_outbound": "Allow"},
        ]
    }


@pytest.fixture
def firewall_fail_data():
    return {
        "profiles": [
            {"name": "Domain", "enabled": False, "default_inbound": "Allow", "default_outbound": "Allow"},
            {"name": "Private", "enabled": True, "default_inbound": "Block", "default_outbound": "Allow"},
            {"name": "Public", "enabled": False, "default_inbound": "Allow", "default_outbound": "Allow"},
        ]
    }


@pytest.fixture
def av_ok_data():
    from datetime import datetime, timezone
    return {
        "providers": [{"displayName": "Windows Defender", "productState": 397568}],
        "signatures_last_updated": datetime.now(timezone.utc).isoformat(),
        "realtime_enabled": True,
    }


@pytest.fixture
def av_no_provider_data():
    return {"providers": [], "signatures_last_updated": None, "realtime_enabled": None}


@pytest.fixture
def system_profile():
    from datetime import datetime, timezone
    from syspulse.models.report import SystemProfile
    return SystemProfile(
        hostname="TEST-HOST",
        os_name="Windows",
        os_version="10.0.22621",
        os_build="22621",
        architecture="AMD64",
        domain_joined=False,
        azure_ad_joined=False,
        current_user="testuser",
        is_admin=False,
        assessed_at=datetime.now(timezone.utc),
    )
