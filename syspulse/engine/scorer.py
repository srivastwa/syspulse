from __future__ import annotations

from syspulse.config import settings
from syspulse.engine.interaction_matrix import INTERACTION_RULES, InteractionRule
from syspulse.models.finding import Severity
from syspulse.models.report import SystemProfile
from syspulse.models.risk import RuleMatch, SystemScore


def _context_multiplier(profile: SystemProfile) -> float:
    """Return a 1.0–1.5 multiplier based on system context."""
    multiplier = 1.0
    if profile.domain_joined:
        multiplier += 0.15   # lateral movement risk
    if profile.azure_ad_joined:
        multiplier += 0.10   # cloud identity exposure
    if profile.is_admin:
        multiplier += 0.15   # running as admin amplifies impact
    return min(multiplier, 1.5)


def _apply_interactions(matches: list[RuleMatch]) -> list[RuleMatch]:
    """Apply cross-finding amplification rules and annotate each match."""
    active_rule_ids = {m.rule_id for m in matches}

    def _triggers_active(rule: InteractionRule) -> bool:
        return all(
            any(rid.startswith(trigger) for rid in active_rule_ids)
            for trigger in rule.triggers
        )

    triggered = [ir for ir in INTERACTION_RULES if _triggers_active(ir)]

    if not triggered:
        return matches

    updated: list[RuleMatch] = []
    for m in matches:
        boosts: list[str] = []
        extra = 0.0
        for ir in triggered:
            if any(m.rule_id.startswith(t) for t in ir.triggers):
                extra += ir.boost
                boosts.append(f"{ir.label}: +{ir.boost}")
        if extra:
            new_score = min(m.final_score + extra, 10.0)
            updated.append(m.model_copy(update={
                "final_score": new_score,
                "interaction_boosts": list(m.interaction_boosts) + boosts,
            }))
        else:
            updated.append(m)

    return updated


def _score_to_tier(score: float) -> str:
    if score >= 8.0:
        return "CRITICAL"
    if score >= 6.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def compute_system_score(matches: list[RuleMatch], profile: SystemProfile) -> SystemScore:
    ctx = _context_multiplier(profile)

    # Apply context multiplier to base scores
    weighted: list[RuleMatch] = []
    for m in matches:
        rule_weight = 1.0  # default; could be loaded from rule YAML in future
        final = min(m.base_score * rule_weight * ctx, 10.0)
        weighted.append(m.model_copy(update={"final_score": final}))

    # Apply cross-finding interaction boosts
    weighted = _apply_interactions(weighted)

    # Sort by final_score descending
    weighted.sort(key=lambda x: x.final_score, reverse=True)

    # Composite: weighted average of top-N
    top_n = weighted[: settings.top_findings_for_score]
    if top_n:
        total_weight = sum(m.final_score for m in top_n)
        composite = total_weight / len(top_n)
        composite = min(composite, 10.0)
    else:
        composite = 0.0

    # Count by severity
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    counts["pass"] = 0
    for m in weighted:
        counts[m.severity.value] = counts.get(m.severity.value, 0) + 1

    return SystemScore(
        overall=round(composite, 1),
        tier=_score_to_tier(composite),
        ranked_matches=weighted,
        counts=counts,
    )
