from __future__ import annotations

from pydantic import BaseModel, Field


class ComplianceControl(BaseModel):
    id: str              # e.g. "CIS-18.9.11"
    title: str
    category: str
    level: int           # CIS level 1 or 2; 0 for non-CIS
    finding_tags: list[str] = Field(default_factory=list)
    check_ids: list[str] = Field(default_factory=list)


class MappingResult(BaseModel):
    framework: str       # "CIS Windows 11", "NIST 800-53", "ISO 27001"
    version: str
    total_controls: int
    passing: int
    failing: int
    not_covered: int
    details: list[ControlResult] = Field(default_factory=list)


class ControlResult(BaseModel):
    control: ComplianceControl
    status: str          # "pass" | "fail" | "not_covered"
    matched_findings: list[str] = Field(default_factory=list)  # finding IDs
