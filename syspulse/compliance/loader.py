from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from syspulse.models.compliance import ComplianceControl

_FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"


class FrameworkDefinition:
    def __init__(self, raw: dict[str, Any]) -> None:
        self.framework: str = raw["framework"]
        self.version: str = str(raw["version"])
        self.controls: list[ComplianceControl] = [
            ComplianceControl(
                id=c["id"],
                title=c["title"],
                category=c["category"],
                level=c.get("level", 0),
            )
            for c in raw.get("controls", [])
        ]


def load_all_frameworks() -> list[FrameworkDefinition]:
    """Load every *.json framework definition from the frameworks/ directory."""
    frameworks: list[FrameworkDefinition] = []
    for path in sorted(_FRAMEWORKS_DIR.glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        frameworks.append(FrameworkDefinition(raw))
    return frameworks
