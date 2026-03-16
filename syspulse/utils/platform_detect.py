from __future__ import annotations

import ctypes
import os
import platform
import sys
from enum import Enum


class Platform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    DARWIN = "darwin"
    UNKNOWN = "unknown"


def current_platform() -> Platform:
    p = sys.platform
    if p == "win32":
        return Platform.WINDOWS
    if p == "linux":
        return Platform.LINUX
    if p == "darwin":
        return Platform.DARWIN
    return Platform.UNKNOWN


def is_admin() -> bool:
    """Return True if the current process has admin/root privileges."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def system_info() -> dict[str, str]:
    """Return basic OS metadata."""
    uname = platform.uname()
    return {
        "os_name": platform.system(),
        "os_version": platform.version(),
        "os_build": uname.release,
        "architecture": platform.machine(),
        "hostname": platform.node(),
    }
