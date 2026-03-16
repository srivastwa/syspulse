from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

_RULES_DIR = Path(__file__).parent / "rules"


class RuleCondition(BaseModel):
    """Simple condition that checks a field in finding.metadata or finding tags."""
    # Match by finding tag
    tag: str | None = None
    # Match by check_id prefix
    check_id_prefix: str | None = None
    # Match by exact check_id
    check_id: str | None = None
    # Match by category
    category: str | None = None
    # Match by status
    status: str | None = None


class Rule(BaseModel):
    id: str
    name: str
    condition: RuleCondition
    base_score: float = Field(ge=0.0, le=10.0)
    severity: str         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    weight: float = 1.0
    cvss_vector: str | None = None
    remediation: list[str] = Field(default_factory=list)
    compliance_tags: list[str] = Field(default_factory=list)


def load_all_rules() -> list[Rule]:
    """Load and validate all YAML rule files from the rules/ directory."""
    rules: list[Rule] = []
    for path in sorted(_RULES_DIR.glob("*.yaml")):
        raw: list[dict[str, Any]] = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        for item in raw:
            rules.append(Rule.model_validate(item))
    return rules
