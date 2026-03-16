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

## Sprint & Phase Plan

### Status Legend
- ✅ Complete
- 🔲 Not started

---

### Phase 1 — Windows

#### Sprint 1 — Foundation ✅
All core scaffolding. Must be complete before any check or engine work.

| Task | File | Status |
|------|------|--------|
| `pyproject.toml` with all dependencies | `pyproject.toml` | ✅ |
| Pydantic models: Finding, Evidence, Severity, CheckStatus | `syspulse/models/finding.py` | ✅ |
| Pydantic models: RuleMatch, SystemScore | `syspulse/models/risk.py` | ✅ |
| Pydantic models: AssessmentReport, SystemProfile | `syspulse/models/report.py` | ✅ |
| Pydantic models: ComplianceControl, MappingResult | `syspulse/models/compliance.py` | ✅ |
| CheckBase ABC + CheckMeta dataclass | `syspulse/checks/base.py` | ✅ |
| importlib auto-discovery registry | `syspulse/checks/registry.py` | ✅ |
| PowerShell subprocess runner (UTF-8, timeout, stderr) | `syspulse/utils/subprocess_runner.py` | ✅ |
| Platform detection + admin check | `syspulse/utils/platform_detect.py` | ✅ |
| Structured logging (structlog) | `syspulse/utils/logging.py` | ✅ |
| Settings (pydantic-settings) | `syspulse/config.py` | ✅ |
| Orchestration runner | `syspulse/runner.py` | ✅ |
| Typer CLI with `--dry-run`, `--format`, `--output`, `--verbose` | `syspulse/cli.py` | ✅ |
| **Milestone:** `python -m syspulse --dry-run` exits 0 | — | ✅ |

#### Sprint 2 — Windows Check Modules ✅
8 check modules + matching PowerShell scripts. Each is independent.

| Check | Python Module | PS Script | Status |
|-------|--------------|-----------|--------|
| Firewall profiles (Domain/Private/Public) | `checks/windows/firewall.py` | `get_firewall_profiles.ps1` | ✅ |
| Antivirus (Security Center WMI, def age) | `checks/windows/antivirus.py` | `get_av_status.ps1` | ✅ |
| BitLocker per-drive encryption | `checks/windows/encryption.py` | `get_bitlocker_status.ps1` | ✅ |
| Windows Update / pending patches | `checks/windows/patching.py` | `get_update_status.ps1` | ✅ |
| Local admins + built-in Administrator | `checks/windows/privileges.py` | `get_local_admins.ps1` | ✅ |
| Misconfigs bundle (SMBv1, Guest, AutoRun, RDP, shares, Secure Boot, password policy) | `checks/windows/misconfigurations.py` | `get_misconfigurations.ps1` | ✅ |
| Backup (VSS, File History, schtasks, third-party) | `checks/windows/backup.py` | `get_backup_status.ps1` | ✅ |
| MFA (AAD join, WHFB, no-password accounts, pwd-never-expires) | `checks/windows/mfa.py` | `get_mfa_status.ps1` | ✅ |
| **Milestone:** `python -m syspulse --format json` dumps real findings | — | ✅ |

#### Sprint 3 — Rule Engine ✅
Deterministic rule-based scoring. No AI.

| Task | File | Status |
|------|------|--------|
| YAML rule schema + Pydantic validation | `engine/rule_loader.py` | ✅ |
| Finding → rule matching (first-match-wins) | `engine/evaluator.py` | ✅ |
| Cross-finding interaction amplification table | `engine/interaction_matrix.py` | ✅ |
| Per-finding score: base × weight × context multiplier | `engine/scorer.py` | ✅ |
| Composite system score (top-10 weighted avg, capped 10.0) | `engine/scorer.py` | ✅ |
| Rule YAML: encryption | `engine/rules/encryption.yaml` | ✅ |
| Rule YAML: antivirus | `engine/rules/antivirus.yaml` | ✅ |
| Rule YAML: firewall | `engine/rules/firewall.yaml` | ✅ |
| Rule YAML: patching | `engine/rules/patching.yaml` | ✅ |
| Rule YAML: privileges | `engine/rules/privileges.yaml` | ✅ |
| Rule YAML: backup | `engine/rules/backup.yaml` | ✅ |
| Rule YAML: mfa | `engine/rules/mfa.yaml` | ✅ |
| Rule YAML: misconfigurations | `engine/rules/misconfigurations.yaml` | ✅ |
| **Milestone:** findings scored with CVSS vectors and interaction boosts | — | ✅ |

#### Sprint 4 — Output Layer ✅

| Task | File | Status |
|------|------|--------|
| Rich terminal dashboard (summary, findings table, compliance, remediation) | `output/terminal.py` | ✅ |
| JSON export (schema-versioned) | `output/json_export.py` | ✅ |
| Jinja2 HTML report (self-contained, no CDN) | `output/html_report.py` + `templates/report.html.j2` | ✅ |
| **Milestone:** all three output formats working end-to-end | — | ✅ |

#### Sprint 5 — Compliance Mapping 🔲
Wire findings to CIS Benchmark, NIST 800-53, ISO 27001 controls.

| Task | File | Status |
|------|------|--------|
| CIS Windows Benchmark control definitions | `compliance/frameworks/cis_windows.json` | 🔲 |
| NIST 800-53 relevant control subset | `compliance/frameworks/nist_800_53.json` | 🔲 |
| ISO 27001 Annex A controls | `compliance/frameworks/iso_27001.json` | 🔲 |
| Framework loader | `compliance/loader.py` | 🔲 |
| Findings → controls mapper (by tag + check_id) | `compliance/mapper.py` | 🔲 |
| Wire compliance results into terminal, JSON, HTML output | — | 🔲 |
| **Milestone:** compliance table shows pass/fail counts per framework | — | 🔲 |

#### Sprint 6 — Polish & Distribution 🔲

| Task | File | Status |
|------|------|--------|
| PyInstaller build script → single `.exe` | `scripts/build_exe.py` | 🔲 |
| Tests for all 8 check modules (mocked PS output) | `tests/unit/checks/` | 🔲 (partial — firewall + AV done) |
| Tests for rule engine (evaluator + interaction boosts) | `tests/unit/engine/` | 🔲 (partial — scorer done) |
| GitHub Actions CI (pytest on push) | `.github/workflows/test.yml` | 🔲 |
| **Milestone:** single `.exe`, full test suite, CI passing | — | 🔲 |

---

### Phase 2 — Linux 🔲
Add `checks/linux/` modules. Runner, engine, models, output require **zero changes**.

| Check | Module | Shell Command(s) | Status |
|-------|--------|-----------------|--------|
| Pending updates | `checks/linux/patching.py` | `apt list --upgradable` / `yum check-update` / `dnf check-update` | 🔲 |
| Firewall | `checks/linux/firewall.py` | `ufw status` / `iptables -L` / `firewall-cmd --state` | 🔲 |
| Disk encryption (LUKS) | `checks/linux/encryption.py` | `lsblk -o NAME,FSTYPE` + `cryptsetup status` | 🔲 |
| Privilege escalation (sudoers, SUID) | `checks/linux/privileges.py` | `cat /etc/sudoers`, `find / -perm -4000` | 🔲 |
| Antivirus (ClamAV, Falcon) | `checks/linux/antivirus.py` | `clamscan --version`, `systemctl status falcon-sensor` | 🔲 |
| SSH hardening | `checks/linux/ssh.py` | `sshd -T` (parse config) | 🔲 |
| World-writable files | `checks/linux/filesystem.py` | `find / -xdev -perm -0002` | 🔲 |
| **Milestone:** `python -m syspulse --format terminal` works on Ubuntu/Debian/RHEL | — | 🔲 |

Note: Linux checks call `run_shell_command()` from `utils/subprocess_runner.py`, not PowerShell. No PS scripts needed.

---

### Phase 3 — macOS 🔲
Add `checks/darwin/` modules. Same pattern as Linux.

| Check | Module | Command(s) | Status |
|-------|--------|-----------|--------|
| Software updates | `checks/darwin/patching.py` | `softwareupdate -l` | 🔲 |
| Application firewall | `checks/darwin/firewall.py` | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | 🔲 |
| FileVault encryption | `checks/darwin/encryption.py` | `fdesetup status` | 🔲 |
| Admin group / sudo | `checks/darwin/privileges.py` | `dscl . -read /Groups/admin GroupMembership` | 🔲 |
| Gatekeeper | `checks/darwin/gatekeeper.py` | `spctl --status` | 🔲 |
| SIP (System Integrity Protection) | `checks/darwin/sip.py` | `csrutil status` | 🔲 |
| **Milestone:** `python -m syspulse --format terminal` works on macOS 13+ | — | 🔲 |

---

## What's NOT Built Yet

- `syspulse/compliance/` — `loader.py` and `mapper.py` are empty stubs; framework JSON files not populated (Sprint 5)
- `checks/linux/` and `checks/darwin/` — empty packages with `__init__.py` only (Phase 2 & 3)
- Missing unit tests for 6 of the 8 Windows check modules (Sprint 6)
- PyInstaller build script (Sprint 6)
- GitHub Actions CI (Sprint 6)

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
