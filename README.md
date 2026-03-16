# SysPulse

A cross-platform security assessment agent that audits Windows endpoints (Linux and macOS planned) for common security misconfigurations, scores findings using a deterministic rule engine, and outputs a prioritized risk dashboard with compliance mapping — all offline, no cloud dependencies.

```
┌─ SysPulse — WORKSTATION-01 — 2026-03-16 ────────────────────────────────────┐
│  Overall Risk: 7.8/10  [HIGH]                                                │
├──────────────┬───────────────────────────────────────────────────────────────┤
│ Summary      │ Critical Findings                                             │
│ Critical: 3  │ 1. SMBv1 Protocol is Enabled                                 │
│ High:     5  │ 2. BitLocker Not Enabled on C:                                │
│ Medium:   2  │ 3. No Antivirus Provider Registered                           │
│ Pass:     8  │                                                               │
├──────────────┴───────────────────────────────────────────────────────────────┤
│ ID             Title                       Severity  Score  CVSS             │
│ WIN-MISC-SMB1  SMBv1 Protocol is Enabled   CRITICAL  9.0    CVSS:3.1/AV:N/  │
│ WIN-ENC-001-C  BitLocker Not Enabled (C:)  CRITICAL  9.1    CVSS:3.1/AV:P/  │
│ WIN-AV-001     No AV Provider Registered   CRITICAL  8.8    CVSS:3.1/AV:N/  │
└──────────────────────────────────────────────────────────────────────────────┘
```

## What It Checks

| Domain | Check | Details |
|--------|-------|---------|
| **MFA** | Azure AD join status, Windows Hello for Business enrollment, local accounts without passwords, password-never-expires accounts | |
| **Patching** | Pending Windows security updates, days since last install | WUA COM object |
| **Backup** | File History, VSS shadow copies, Windows Backup, third-party (Veeam, Acronis, etc.) | |
| **Privileges** | Local administrator enumeration, built-in Administrator account enabled, excess admin count | |
| **Encryption** | BitLocker status per drive, protection on/off, key protector types | |
| **Firewall** | Defender Firewall profiles (Domain/Private/Public) enabled/disabled | |
| **Antivirus** | Security Center registered providers, definition staleness, real-time protection | |
| **Misconfigurations** | SMBv1, Guest account, AutoRun/AutoPlay, RDP without NLA, open network shares, Secure Boot, weak password policy | |

## How Risk Scoring Works

No AI, no cloud — all scoring is deterministic and runs entirely offline.

1. **Check modules** run PowerShell scripts and emit `Finding` objects with a default severity
2. **Rule engine** matches each finding against YAML rules in `syspulse/engine/rules/`. Each rule has a `base_score` (0–10), `weight`, and optional `cvss_vector`
3. **Context multiplier** (1.0–1.5) adjusts scores based on system profile: domain-joined, Azure AD joined, running as admin
4. **Interaction penalties** amplify correlated risks:
   - No AV + Firewall disabled → +1.5 to each
   - SMBv1 + patches missing → +2.0 to each
   - No encryption + open shares → +1.0 to each
   - No MFA + excess local admins → +1.5 to each
5. **System score** = weighted average of the top-10 final scores, capped at 10.0

Risk tiers: `CRITICAL` (≥8.0) · `HIGH` (≥6.0) · `MEDIUM` (≥4.0) · `LOW` (<4.0)

## Compliance Mapping

Findings are tagged with control IDs. The compliance engine maps them to:

- **CIS Microsoft Windows Benchmark** (19 controls)
- **NIST SP 800-53** (13 controls)
- **ISO/IEC 27001:2022** (11 controls, Annex A)

Each rule YAML includes `compliance_tags` such as `CIS-18.3.3`, `NIST-CM-7`, `ISO-A.12.6.1`.

## Output

Every run always produces **two outputs**:

| Output | Description |
|--------|-------------|
| **Terminal dashboard** | Rich-rendered panels with summary, findings table, compliance coverage, remediation steps |
| **HTML report** | Self-contained dark-theme file, auto-named `eciso-syspulse-<hostname>-<ddmmyy>.html` |

Optionally, select **Option 2** at the startup menu to also submit the report as JSON to the eCISO web dashboard (see below).

## eCISO Web Dashboard

A companion FastAPI web app that receives submitted reports and displays them on a central dashboard.

### Start the server

```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
# or: make serve-install && make serve
```

Open http://localhost:8000 — the dashboard shows all submitted reports with risk tier badges, finding counts, and drill-down to full report details including compliance coverage bars.

### Submit from SysPulse

When prompted at startup, select **Option 2** — the agent runs the full assessment and POSTs the JSON report to the server automatically.

To point SysPulse at a remote server, set `ECISO_SERVER_URL` in a `.env` file:

```
ECISO_SERVER_URL=http://your-server:8000
```

## Installation

**Requirements:** Python 3.8+, Windows (for actual checks — dry-run and the server work on any OS)

```bash
git clone https://github.com/srivastwa/syspulse
cd syspulse
pip install -e .
```

Or install deps directly:
```bash
pip install pydantic pydantic-settings pyyaml rich typer jinja2 structlog eval_type_backport typing_extensions
```

## Usage

```bash
# Full security assessment (shows startup menu)
python -m syspulse

# Skip menu — generate report only, no prompt
python -m syspulse --no-menu

# Dry run (no checks, tests the pipeline)
python -m syspulse --dry-run

# Save HTML report to a custom path
python -m syspulse --output /tmp/my-report.html

# Verbose debug logging
python -m syspulse --verbose
```

**Startup menu:**
```
  ┌─ SysPulse — Select Action ──────────────────────────────┐
  │                                                          │
  │    1  Generate Report                                    │
  │    2  Generate Report and Submit to eCISO               │
  │                                                          │
  └──────────────────────────────────────────────────────────┘
  Choice [1/2] (1):
```

**Note:** Run from an elevated (Administrator) command prompt for complete results. Some checks (BitLocker, certain registry reads) require admin privileges.

## Project Structure

```
syspulse/
├── syspulse/
│   ├── checks/
│   │   ├── base.py              # CheckBase ABC — all checks implement this
│   │   ├── registry.py          # auto-discovers check classes via importlib
│   │   └── windows/             # 8 Windows check modules
│   │       ├── antivirus.py
│   │       ├── backup.py
│   │       ├── encryption.py
│   │       ├── firewall.py
│   │       ├── mfa.py
│   │       ├── misconfigurations.py
│   │       ├── patching.py
│   │       └── privileges.py
│   ├── engine/
│   │   ├── evaluator.py         # matches findings → rules
│   │   ├── interaction_matrix.py # cross-finding amplification table
│   │   ├── rule_loader.py       # loads + validates YAML rule files
│   │   ├── scorer.py            # per-finding and composite scoring
│   │   └── rules/               # 8 YAML rule files with CVSS vectors
│   ├── compliance/              # CIS / NIST 800-53 / ISO 27001 mapping
│   ├── models/                  # Pydantic data models (Finding, RuleMatch, etc.)
│   ├── output/                  # terminal, json, html renderers
│   ├── ps_scripts/              # PowerShell scripts (one per check domain)
│   ├── runner.py                # orchestrates checks → engine → output
│   └── cli.py                   # Typer CLI + startup menu
├── server/
│   ├── main.py                  # FastAPI app
│   ├── database.py              # SQLite store
│   ├── templates/               # Jinja2 dashboard + report templates
│   └── static/                  # CSS
└── tests/
    ├── unit/checks/             # per-check tests with mocked PS output
    ├── unit/engine/             # scorer, evaluator, compliance tests
    └── integration/             # full dry-run end-to-end tests
```

## Adding a New Check

1. Create `syspulse/checks/windows/my_check.py` with a class inheriting `CheckBase`:

```python
from syspulse.checks.base import CheckBase, CheckMeta
from syspulse.models.finding import Finding, Severity, CheckStatus

class MyCheck(CheckBase):
    meta = CheckMeta(
        id="WIN-MY-001",
        name="My Security Check",
        category="my_category",
        platform="windows",
    )

    def run(self) -> list[Finding]:
        # ... collect data, return Finding objects
```

2. Create a matching `syspulse/ps_scripts/get_my_data.ps1` that outputs JSON to stdout

3. Add a rule in `syspulse/engine/rules/my_category.yaml`

The check is auto-discovered at runtime — no registration needed.

## Adding a New Rule

Rules in `syspulse/engine/rules/*.yaml` follow this schema:

```yaml
- id: RULE-MY-001
  name: Descriptive rule name
  condition:
    check_id_prefix: WIN-MY    # or: check_id, category, status, tag
  base_score: 7.5              # 0.0–10.0
  severity: HIGH               # CRITICAL | HIGH | MEDIUM | LOW | INFO
  weight: 1.2                  # score multiplier
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
  remediation:
    - "Step 1: do this"
    - "Step 2: do that"
  compliance_tags:
    - "CIS-x.x.x"
    - "NIST-XX-1"
    - "ISO-A.x.x.x"
```

## Running Tests

```bash
pip install pytest pytest-mock
pytest tests/ -v
# or: make test
```

Tests mock the PowerShell subprocess layer so they run on any platform (49 tests total).

## Makefile

```bash
make install        # pip install -e ".[dev]"
make test           # pytest tests/ -v
make run            # python3 -m syspulse
make dry-run        # python3 -m syspulse --dry-run --no-menu
make lint           # ruff check + mypy
make fmt            # ruff format
make serve-install  # pip install -r server/requirements.txt
make serve          # start eCISO dashboard at http://localhost:8000
```

## Hosting the eCISO Server

The eCISO server can be hosted anywhere Python runs. Agents on any machine point to it via a URL.

### Option 1 — Local network

Run on any machine on your network:

```bash
pip install -r server/requirements.txt
cd server
uvicorn main:app --host 0.0.0.0 --port 8000
```

`--host 0.0.0.0` makes it reachable from other machines, not just localhost. Open `http://<server-ip>:8000` in a browser.

### Option 2 — Cloud VM (persistent)

On any VPS (AWS EC2, DigitalOcean, Hetzner, etc.), run as a systemd service so it survives reboots:

```bash
git clone https://github.com/srivastwa/syspulse
cd syspulse && pip install -r server/requirements.txt

sudo tee /etc/systemd/system/eciso.service <<EOF
[Unit]
Description=eCISO SysPulse Server
After=network.target

[Service]
WorkingDirectory=/root/syspulse/server
ExecStart=uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now eciso
```

Open port 8000 in your firewall, or put nginx in front with HTTPS on port 443.

### Option 3 — Fly.io / Railway / Render (free tier)

Deploy directly from GitHub. Set the start command to:

```
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Working directory: `server/`. Attach a persistent volume to preserve the SQLite database across redeploys.

---

## Pointing Agents at the Server

Three ways to configure the server URL, in order of preference:

**1. `.env` file** (place next to where you run `python -m syspulse`):
```
ECISO_SERVER_URL=http://192.168.1.50:8000
```

**2. Environment variable** (one-off or CI):
```bash
ECISO_SERVER_URL=http://your-server:8000 python -m syspulse
```

**3. Default in `syspulse/config.py`** (if all agents always hit the same server):
```python
eciso_server_url: str = "http://your-server:8000"
```

### Verify connectivity

Test from the agent machine before running a scan:

```bash
curl -s http://your-server:8000/api/reports \
     -X POST \
     -H "Content-Type: application/json" \
     -d '{"system":{"hostname":"test"},"score":{"overall":5.0,"tier":"MEDIUM","counts":{}}}'
# expected: {"id": 1, "status": "accepted"}
```

Then run `python -m syspulse`, select **Option 2**, and the report will appear at `http://your-server:8000`.

---

## Roadmap

- [ ] **Phase 2 — Linux**: `checks/linux/` modules (ufw/iptables, LUKS, apt/yum, sudoers, ClamAV, SSH hardening)
- [ ] **Phase 3 — macOS**: `checks/darwin/` modules (pf, FileVault, softwareupdate, admin group, Gatekeeper, SIP)
- [ ] **PyInstaller build**: single `.exe` with no Python dependency for Windows deployment
- [ ] **Historical trending**: compare assessments over time, track score changes in eCISO dashboard

## License

MIT
