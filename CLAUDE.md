# CLAUDE.md — SysPulse Project Context

This file gives Claude context for working in this repository.

## What This Project Is

SysPulse is a cross-platform security assessment agent. It runs security checks on a local machine, scores findings using a deterministic internal rule engine (no AI/cloud), and renders a risk dashboard with compliance mapping (CIS, NIST 800-53, ISO 27001).

**Phase 1 (complete):** Windows endpoint checks
**Phase 2 (planned):** Linux
**Phase 3 (planned):** macOS

## Tech Stack

- **Python 3.8+** orchestrates everything
- **PowerShell** scripts in `syspulse/ps_scripts/` collect Windows data — each outputs a single JSON object to stdout and exits 0
- **Pydantic v2** for all data models — the models are the contract between modules
- **Rich** for terminal dashboard
- **Typer** for CLI (single-command app — invoke as `python -m syspulse --format terminal`, NOT `python -m syspulse scan`)
- **Jinja2** for HTML report
- **PyYAML** for rule definitions
- `eval_type_backport` and `typing_extensions` required for Python 3.8 compatibility

## Architecture

```
CLI (cli.py) → Runner (runner.py) → Check Registry (checks/registry.py)
                                  ↓
                          Windows Checks (checks/windows/*.py)
                          each calls a ps_scripts/*.ps1
                                  ↓
                          Rule Engine (engine/)
                          evaluator.py → scorer.py → interaction_matrix.py
                                  ↓
                          Output (output/terminal.py | json_export.py | html_report.py)
```

## Key Architectural Decisions

**PowerShell subprocess isolation:** Every `.ps1` runs in a fresh `powershell.exe -NoProfile -NonInteractive` process. Each script outputs exactly one JSON object. This makes every check independently testable by mocking `run_powershell_script`.

**Auto-discovery:** `checks/registry.py` uses `importlib` + `pkgutil` to walk the `checks/<platform>/` package and collect all `CheckBase` subclasses. Adding a new check file is sufficient — no registration needed.

**Rule engine (not AI):** Risk scoring is deterministic. Rules live in `engine/rules/*.yaml`. The user explicitly chose NOT to use AI for scoring — keep it that way unless asked.

**First matching rule wins:** In `evaluator.py`, once a rule matches a finding, evaluation stops. Rules should be ordered most-specific → least-specific within each YAML file.

**Fail-safe error findings:** If a check's PowerShell script fails, the check emits an `ERROR`-status finding rather than crashing the whole run.

**Pydantic as the integration boundary:** Every module boundary is crossed via Pydantic models. Don't add parallel data structures.

## Data Model Summary

```
Finding          → produced by check modules; has severity, status, evidence, tags
RuleMatch        → Finding + rule scoring (base_score, final_score, CVSS, remediation)
SystemScore      → all RuleMatches ranked + composite 0–10 score + counts
AssessmentReport → SystemProfile + SystemScore + compliance results
```

## File Map — Where Things Live

| Purpose | File |
|---------|------|
| CLI entry | `syspulse/cli.py` |
| Orchestration | `syspulse/runner.py` |
| Check contract | `syspulse/checks/base.py` |
| Check discovery | `syspulse/checks/registry.py` |
| Windows checks | `syspulse/checks/windows/*.py` |
| PS scripts | `syspulse/ps_scripts/*.ps1` |
| Rule YAML | `syspulse/engine/rules/*.yaml` |
| Rule loading | `syspulse/engine/rule_loader.py` |
| Rule evaluation | `syspulse/engine/evaluator.py` |
| Scoring | `syspulse/engine/scorer.py` |
| Interaction boosts | `syspulse/engine/interaction_matrix.py` |
| Data models | `syspulse/models/` |
| Terminal output | `syspulse/output/terminal.py` |
| HTML template | `syspulse/output/templates/report.html.j2` |
| Settings | `syspulse/config.py` |
| PS runner util | `syspulse/utils/subprocess_runner.py` |
| Platform detect | `syspulse/utils/platform_detect.py` |

## Check Module Pattern

Every check module follows this pattern — don't deviate:

```python
class FooCheck(CheckBase):
    meta = CheckMeta(id="WIN-FOO-001", name="...", category="foo", platform="windows")

    def run(self) -> list[Finding]:
        try:
            data = run_powershell_script("get_foo.ps1")
        except (SubprocessError, FileNotFoundError) as exc:
            return [_error_finding(self.meta.id, str(exc))]
        # ... emit Finding objects
        return findings

def _error_finding(check_id: str, msg: str) -> Finding:
    return Finding(id=f"{check_id}-ERROR", check_id=check_id, ..., status=CheckStatus.ERROR, ...)
```

## Rule YAML Pattern

```yaml
- id: RULE-CAT-001           # RULE-{CATEGORY}-{NUMBER}
  name: Human readable name
  condition:
    check_id_prefix: WIN-CAT  # match by prefix, exact check_id, category, status, or tag
  base_score: 7.5             # 0.0–10.0
  severity: HIGH
  weight: 1.2
  cvss_vector: "CVSS:3.1/..."
  remediation:
    - "Concrete actionable step"
  compliance_tags:
    - "CIS-x.x"
    - "NIST-XX-1"
```

## Interaction Matrix

`engine/interaction_matrix.py` contains `INTERACTION_RULES`. Each rule's `triggers` are **rule ID prefixes** (e.g. `"RULE-AV"` matches `RULE-AV-001`). When ALL triggers are present in the active match set, `boost` is added to each matching finding's `final_score`. When adding new categories, consider whether they should interact with existing ones.

## Test Conventions

- All tests mock `run_powershell_script` — tests must run on macOS/Linux without PowerShell
- Fixtures in `tests/conftest.py` — add shared fixture data there
- Integration tests in `tests/integration/` use `dry_run=True` only
- Unit check tests go in `tests/unit/checks/test_{check_name}.py`
- Unit engine tests go in `tests/unit/engine/`
- Run with: `python3 -m pytest tests/ -v`

## Python 3.8 Compatibility Notes

The system Python is 3.8.3. Keep these in mind:
- `Annotated` must be imported from `typing_extensions` (done in `cli.py`)
- `eval_type_backport` is required for Pydantic to evaluate `dict[str, Any] | str` syntax
- `from __future__ import annotations` is at the top of every module — this is required
- Don't use `match` statements (3.10+), `ExceptionGroup` (3.11+), or `tomllib` (3.11+)

## What's NOT Built Yet (Roadmap)

- `syspulse/compliance/` — loader and mapper modules are stubs; frameworks JSON not populated
- `checks/linux/` and `checks/darwin/` — empty packages, no check modules yet
- PyInstaller build script
- Historical trending / assessment comparison
- GitHub Actions CI

## Development Commands

```bash
make install    # pip install -e ".[dev]"
make test       # pytest tests/ -v
make dry-run    # python3 -m syspulse --dry-run --format terminal
make scan-json  # python3 -m syspulse --format json
make scan-html  # python3 -m syspulse --format html --output report.html && open report.html
make lint       # ruff check + mypy
make fmt        # ruff format
```

## GitHub

Repo: https://github.com/srivastwa/syspulse
Branch: `main`
