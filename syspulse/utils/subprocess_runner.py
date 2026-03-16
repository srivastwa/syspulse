from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

# PowerShell scripts live next to the syspulse package
_PS_SCRIPTS_DIR = Path(__file__).parent.parent / "ps_scripts"


class SubprocessError(Exception):
    def __init__(self, script: str, returncode: int, stderr: str) -> None:
        self.script = script
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"{script} exited {returncode}: {stderr[:300]}")


def run_powershell_script(script_name: str, timeout: int = 30) -> dict[str, Any]:
    """
    Run a PowerShell script from ps_scripts/ and return its stdout parsed as JSON.

    Each script must:
    - Output a single JSON object to stdout
    - Exit 0 on success, non-zero on error
    """
    script_path = _PS_SCRIPTS_DIR / script_name
    if not script_path.exists():
        raise FileNotFoundError(f"PS script not found: {script_path}")

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy", "Bypass",
            "-File", str(script_path),
        ],
        capture_output=True,
        timeout=timeout,
        # PowerShell outputs UTF-16LE on Windows; decode errors fallback gracefully
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        raise SubprocessError(script_name, result.returncode, result.stderr)

    stdout = result.stdout.strip()
    if not stdout:
        return {}

    try:
        return json.loads(stdout)  # type: ignore[no-any-return]
    except json.JSONDecodeError as exc:
        raise SubprocessError(script_name, 0, f"Invalid JSON output: {exc}") from exc


def run_shell_command(args: list[str], timeout: int = 30) -> str:
    """Run an arbitrary shell command and return stdout as a string (for Linux/macOS checks)."""
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise SubprocessError(args[0], result.returncode, result.stderr)
    return result.stdout.strip()
