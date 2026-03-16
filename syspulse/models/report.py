from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from syspulse.models.compliance import MappingResult
from syspulse.models.inventory import SystemInventory
from syspulse.models.risk import SystemScore


class SystemProfile(BaseModel):
    hostname: str
    os_name: str
    os_version: str
    os_build: str
    architecture: str
    domain_joined: bool
    azure_ad_joined: bool
    current_user: str
    is_admin: bool
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssessmentReport(BaseModel):
    schema_version: str = "1.0"
    tool_version: str = "0.1.0"
    system: SystemProfile
    score: SystemScore
    compliance_results: list[MappingResult] = Field(default_factory=list)
    inventory: Optional[SystemInventory] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
