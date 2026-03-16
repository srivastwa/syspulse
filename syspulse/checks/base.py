from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from syspulse.models.finding import Finding


@dataclass
class CheckMeta:
    id: str                    # e.g. "WIN-AV-001"
    name: str
    category: str
    platform: str              # "windows" | "linux" | "darwin" | "all"
    requires_admin: bool = False
    tags: list[str] = field(default_factory=list)


class CheckBase(ABC):
    meta: CheckMeta  # must be defined as a class-level attribute

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute the check and return zero or more findings."""
        ...

    def is_applicable(self, platform: str, is_admin: bool) -> bool:
        if self.meta.platform != "all" and self.meta.platform != platform:
            return False
        if self.meta.requires_admin and not is_admin:
            return False
        return True
