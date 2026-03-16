from __future__ import annotations

from dataclasses import dataclass


@dataclass
class InteractionRule:
    """
    When all rule_ids in `triggers` are present in the match set,
    add `boost` to each of those matches' final_score.
    """
    id: str
    triggers: list[str]   # rule IDs or tag patterns that must ALL be present
    boost: float
    label: str            # human-readable description of the interaction


# Predefined cross-finding risk amplifications.
# triggers use prefix matching on rule_id (e.g. "RULE-AV" matches RULE-AV-001).
INTERACTION_RULES: list[InteractionRule] = [
    InteractionRule(
        id="INT-001",
        triggers=["RULE-AV", "RULE-FW"],
        boost=1.5,
        label="No AV + Firewall disabled",
    ),
    InteractionRule(
        id="INT-002",
        triggers=["RULE-MISC-SMB", "RULE-PATCH"],
        boost=2.0,
        label="SMBv1 enabled + patches missing",
    ),
    InteractionRule(
        id="INT-003",
        triggers=["RULE-ENC", "RULE-MISC-SHARE"],
        boost=1.0,
        label="No encryption + open shares",
    ),
    InteractionRule(
        id="INT-004",
        triggers=["RULE-MFA", "RULE-PRIV"],
        boost=1.5,
        label="No MFA + excessive local admin accounts",
    ),
]
