from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    ERROR = "error"    # check itself failed to run
    SKIPPED = "skipped"  # not applicable on this platform


class Evidence(BaseModel):
    source: str                        # e.g. "powershell:get_av_status.ps1"
    raw_output: dict[str, Any] | str   # parsed JSON or raw string fallback
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Finding(BaseModel):
    id: str                            # stable: "WIN-AV-001-NO-AV"
    check_id: str                      # module that produced it: "WIN-AV-001"
    title: str
    description: str
    severity: Severity                 # check-module default; rule engine may override
    status: CheckStatus
    platform: str                      # "windows" | "linux" | "darwin"
    category: str                      # "antivirus" | "patching" | ...
    evidence: list[Evidence] = Field(default_factory=list)
    affected_resources: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
