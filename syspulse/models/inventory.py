from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class CpuInfo(BaseModel):
    name: str
    cores: int = 0
    logical_processors: int = 0
    max_clock_speed_mhz: int = 0
    l2_cache_kb: Optional[int] = None
    l3_cache_kb: Optional[int] = None
    architecture: Optional[str] = None


class MotherboardInfo(BaseModel):
    manufacturer: str
    product: str
    serial_number: Optional[str] = None
    bios_version: Optional[str] = None
    bios_date: Optional[str] = None


class MemoryModule(BaseModel):
    capacity_gb: float
    speed_mhz: Optional[int] = None
    manufacturer: Optional[str] = None
    part_number: Optional[str] = None
    form_factor: Optional[str] = None


class DiskDrive(BaseModel):
    model: str
    size_gb: float
    media_type: Optional[str] = None
    interface_type: Optional[str] = None
    serial_number: Optional[str] = None
    partitions: Optional[int] = None


class DisplayAdapter(BaseModel):
    name: str
    vram_mb: Optional[int] = None
    driver_version: Optional[str] = None
    resolution: Optional[str] = None


class PrinterInfo(BaseModel):
    name: str
    driver_name: Optional[str] = None
    is_default: bool = False
    is_network: bool = False


class UsbDevice(BaseModel):
    name: str
    device_id: Optional[str] = None
    manufacturer: Optional[str] = None


class BatteryInfo(BaseModel):
    name: str
    design_capacity_mwh: Optional[int] = None
    full_charge_capacity_mwh: Optional[int] = None
    charge_remaining_pct: Optional[int] = None
    status: Optional[str] = None


class SoftwareItem(BaseModel):
    name: str
    version: Optional[str] = None
    publisher: Optional[str] = None
    install_date: Optional[str] = None
    install_location: Optional[str] = None
    product_key: Optional[str] = None
    source: Optional[str] = None  # registry, appx, electron-local, winget, etc.


class NetworkAdapter(BaseModel):
    name: str
    description: Optional[str] = None
    mac_address: Optional[str] = None
    ip_addresses: List[str] = []
    speed_mbps: Optional[int] = None
    status: str = "Unknown"


class NetworkShare(BaseModel):
    name: str
    path: str
    description: Optional[str] = None


class MappedDrive(BaseModel):
    drive_letter: str
    remote_path: str


class LocalUser(BaseModel):
    name: str
    full_name: Optional[str] = None
    enabled: bool = True
    last_logon: Optional[str] = None
    password_required: bool = True
    password_expires: bool = True
    groups: List[str] = []


class BrowserExtension(BaseModel):
    browser: str
    extension_id: str
    name: str
    version: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True


class NetworkHost(BaseModel):
    ip: str
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: str = "Unknown"
    os_confidence: str = "low"   # low | medium | high
    open_ports: List[int] = []
    services: List[str] = []
    is_local: bool = False
    response_time_ms: Optional[int] = None
    ttl: Optional[int] = None


class SystemInventory(BaseModel):
    # Hardware
    cpu: List[CpuInfo] = []
    motherboard: Optional[MotherboardInfo] = None
    memory_modules: List[MemoryModule] = []
    total_ram_gb: float = 0.0
    disks: List[DiskDrive] = []
    display_adapters: List[DisplayAdapter] = []
    printers: List[PrinterInfo] = []
    usb_devices: List[UsbDevice] = []
    battery: Optional[BatteryInfo] = None
    # Software
    software: List[SoftwareItem] = []
    windows_product_id: Optional[str] = None
    # Network
    network_adapters: List[NetworkAdapter] = []
    shared_folders: List[NetworkShare] = []
    mapped_drives: List[MappedDrive] = []
    user_accounts: List[LocalUser] = []
    # Browsers
    browser_extensions: List[BrowserExtension] = []
    # Network scan
    network_hosts: List[NetworkHost] = []
