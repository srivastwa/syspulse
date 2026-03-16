from __future__ import annotations

import importlib
import inspect
import pkgutil
from types import ModuleType

from syspulse.checks.base import CheckBase


def _walk_package(package: ModuleType) -> list[type[CheckBase]]:
    checks: list[type[CheckBase]] = []
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):  # type: ignore[attr-defined]
        module = importlib.import_module(f"{package.__name__}.{module_name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, CheckBase) and obj is not CheckBase and hasattr(obj, "meta"):
                checks.append(obj)
    return checks


def discover_checks(platform: str) -> list[type[CheckBase]]:
    """Return all CheckBase subclasses registered for the given platform."""
    try:
        package = importlib.import_module(f"syspulse.checks.{platform}")
    except ModuleNotFoundError:
        return []
    return _walk_package(package)
