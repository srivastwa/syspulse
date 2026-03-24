"""
Inventory collector — runs the four PS scripts and assembles a SystemInventory.
All failures are soft: a failed script produces an empty section, never an exception.
"""
from __future__ import annotations

from typing import Any

from syspulse.models.inventory import (
    BatteryInfo,
    BrowserExtension,
    CpuInfo,
    DiskDrive,
    DisplayAdapter,
    LocalUser,
    MappedDrive,
    MemoryModule,
    MotherboardInfo,
    NetworkAdapter,
    NetworkHost,
    NetworkShare,
    PrinterInfo,
    SecurityAgent,
    SoftwareItem,
    SystemInventory,
    UsbDevice,
)
from syspulse.utils.logging import get_logger
from syspulse.utils.subprocess_runner import SubprocessError, run_powershell_script

log = get_logger(__name__)


def _safe_run(script: str, timeout: int = 30) -> dict[str, Any]:
    """Run a PS script and return the parsed dict; return {} on any error."""
    try:
        return run_powershell_script(script, timeout=timeout)
    except (SubprocessError, FileNotFoundError, Exception) as exc:
        log.warning("inventory script failed", script=script, error=str(exc))
        return {}


def collect_inventory() -> SystemInventory:
    """Collect full system inventory. Never raises."""
    inv = SystemInventory()

    # ── Hardware ─────────────────────────────────────────────────────────────
    hw = _safe_run("get_hardware_info.ps1")

    for c in hw.get("cpu") or []:
        try:
            inv.cpu.append(CpuInfo(**{k: v for k, v in c.items() if v is not None or k == "name"}))
        except Exception:
            pass

    mobo = hw.get("motherboard")
    if mobo:
        try:
            inv.motherboard = MotherboardInfo(**mobo)
        except Exception:
            pass

    for m in hw.get("memory_modules") or []:
        try:
            inv.memory_modules.append(MemoryModule(**m))
        except Exception:
            pass

    inv.total_ram_gb = float(hw.get("total_ram_gb") or 0.0)

    for d in hw.get("disks") or []:
        try:
            inv.disks.append(DiskDrive(**d))
        except Exception:
            pass

    for g in hw.get("display_adapters") or []:
        try:
            inv.display_adapters.append(DisplayAdapter(**g))
        except Exception:
            pass

    for p in hw.get("printers") or []:
        try:
            inv.printers.append(PrinterInfo(**p))
        except Exception:
            pass

    for u in hw.get("usb_devices") or []:
        try:
            inv.usb_devices.append(UsbDevice(**u))
        except Exception:
            pass

    bat = hw.get("battery")
    if bat:
        try:
            inv.battery = BatteryInfo(**bat)
        except Exception:
            pass

    # ── Software ─────────────────────────────────────────────────────────────
    sw = _safe_run("get_software_inventory.ps1")

    for item in sw.get("software") or []:
        try:
            inv.software.append(SoftwareItem(**item))
        except Exception:
            pass

    inv.windows_product_id = sw.get("windows_product_id")

    # ── Network ──────────────────────────────────────────────────────────────
    net = _safe_run("get_network_inventory.ps1")

    for a in net.get("network_adapters") or []:
        try:
            inv.network_adapters.append(NetworkAdapter(**a))
        except Exception:
            pass

    for s in net.get("shared_folders") or []:
        try:
            inv.shared_folders.append(NetworkShare(**s))
        except Exception:
            pass

    for md in net.get("mapped_drives") or []:
        try:
            inv.mapped_drives.append(MappedDrive(**md))
        except Exception:
            pass

    for u in net.get("user_accounts") or []:
        try:
            inv.user_accounts.append(LocalUser(**u))
        except Exception:
            pass

    # ── Browser extensions ───────────────────────────────────────────────────
    bx = _safe_run("get_browser_extensions.ps1")

    for ext in bx.get("extensions") or []:
        try:
            inv.browser_extensions.append(BrowserExtension(**ext))
        except Exception:
            pass

    # ── Security agents ──────────────────────────────────────────────────────
    sa = _safe_run("get_security_agents.ps1", timeout=30)

    for agent in sa.get("security_agents") or []:
        try:
            inv.security_agents.append(SecurityAgent(**{
                k: v for k, v in agent.items()
                if k in SecurityAgent.model_fields
            }))
        except Exception:
            pass

    log.info(
        "inventory collected",
        software=len(inv.software),
        extensions=len(inv.browser_extensions),
        users=len(inv.user_accounts),
        disks=len(inv.disks),
        security_agents=len(inv.security_agents),
    )
    return inv


def collect_network_scan(inv: SystemInventory) -> None:
    """Run the network scan and append results to an existing SystemInventory. Never raises."""
    # Allow up to 90s: async pings ~3s + port checks ~1.2s shared across all live hosts × ports
    ns = _safe_run("get_network_scan.ps1", timeout=90)

    for h in ns.get("hosts") or []:
        try:
            inv.network_hosts.append(NetworkHost(**{
                k: v for k, v in h.items()
                if k in NetworkHost.model_fields
            }))
        except Exception:
            pass

    log.info("network scan complete", network_hosts=len(inv.network_hosts))
