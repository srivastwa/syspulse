from __future__ import annotations

from pydantic import BaseModel, Field

from syspulse.models.finding import Finding, Severity


class RuleMatch(BaseModel):
    finding: Finding
    rule_id: str
    base_score: float                   # from rule YAML (0.0–10.0)
    final_score: float                  # after weight × context × interaction boosts
    severity: Severity                  # rule-defined, overrides check default
    cvss_vector: str | None = None      # manually authored in rule YAML
    remediation_steps: list[str] = Field(default_factory=list)
    compliance_tags: list[str] = Field(default_factory=list)
    interaction_boosts: list[str] = Field(default_factory=list)  # e.g. "NO_AV+NO_FW: +1.5"


class SystemScore(BaseModel):
    overall: float                      # 0.0–10.0 composite
    tier: str                           # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    ranked_matches: list[RuleMatch]     # sorted by final_score descending
    counts: dict[str, int]             # {"critical": 2, "high": 4, "medium": 3, "low": 1, "pass": 12}
