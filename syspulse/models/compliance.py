from __future__ import annotations

from pydantic import BaseModel, Field


class ComplianceControl(BaseModel):
    id: str              # e.g. "CIS-18.9.11.1.1"
    title: str
    category: str
    level: int           # CIS level 1 or 2; 0 for non-CIS frameworks


class ControlResult(BaseModel):
    control: ComplianceControl
    status: str                              # "pass" | "fail" | "not_covered"
    matched_finding_ids: list[str] = Field(default_factory=list)


class MappingResult(BaseModel):
    framework: str       # "CIS Microsoft Windows 11 Benchmark v2.0"
    version: str
    total_controls: int
    passing: int
    failing: int
    not_covered: int
    pass_rate: float     # 0.0–100.0 percentage of covered controls passing
    details: list[ControlResult] = Field(default_factory=list)


# Required for forward references in Pydantic v2
MappingResult.model_rebuild()
