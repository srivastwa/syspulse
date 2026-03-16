# get_hardware_info.ps1 — Collect hardware inventory
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

# CPU
$cpuRaw = Get-CimInstance Win32_Processor | Select-Object `
    Name, NumberOfCores, NumberOfLogicalProcessors,
    MaxClockSpeed, L2CacheSize, L3CacheSize, Architecture

$archMap = @{ 0='x86'; 1='MIPS'; 2='Alpha'; 3='PowerPC'; 5='ARM'; 6='ia64'; 9='x64' }
$cpu = @($cpuRaw | ForEach-Object {
    @{
        name                 = $_.Name.Trim()
        cores                = [int]($_.NumberOfCores)
        logical_processors   = [int]($_.NumberOfLogicalProcessors)
        max_clock_speed_mhz  = [int]($_.MaxClockSpeed)
        l2_cache_kb          = if ($_.L2CacheSize) { [int]$_.L2CacheSize } else { $null }
        l3_cache_kb          = if ($_.L3CacheSize) { [int]$_.L3CacheSize } else { $null }
        architecture         = $archMap[[int]($_.Architecture)]
    }
})

# Motherboard + BIOS
$moboRaw = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
$biosRaw  = Get-CimInstance Win32_BIOS    | Select-Object -First 1
$motherboard = if ($moboRaw) {
    @{
        manufacturer  = ($moboRaw.Manufacturer -replace '\s+', ' ').Trim()
        product       = ($moboRaw.Product -replace '\s+', ' ').Trim()
        serial_number = $moboRaw.SerialNumber
        bios_version  = $biosRaw.SMBIOSBIOSVersion
        bios_date     = if ($biosRaw.ReleaseDate) { $biosRaw.ReleaseDate.ToString('yyyy-MM-dd') } else { $null }
    }
} else { $null }

# RAM modules
$formFactorMap = @{ 0='Unknown'; 1='Other'; 2='SIP'; 3='DIP'; 4='ZIP'; 5='SOJ'; 6='Proprietary';
    7='SIMM'; 8='DIMM'; 9='TSOP'; 10='PGA'; 11='RIMM'; 12='SODIMM'; 13='SRIMM'; 14='SMD';
    15='SSMP'; 16='QFP'; 17='TQFP'; 18='SOIC'; 19='LCC'; 20='PLCC'; 21='BGA'; 22='FPBGA'; 23='LGA' }
$ramModules = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
    @{
        capacity_gb  = [math]::Round($_.Capacity / 1GB, 1)
        speed_mhz    = if ($_.Speed) { [int]$_.Speed } else { $null }
        manufacturer = $_.Manufacturer
        part_number  = ($_.PartNumber -replace '\s+', ' ').Trim()
        form_factor  = $formFactorMap[[int]($_.FormFactor)]
    }
})
$totalRamGb = [math]::Round(($ramModules | Measure-Object -Property capacity_gb -Sum).Sum, 1)

# Disks
$disks = @(Get-CimInstance Win32_DiskDrive | ForEach-Object {
    @{
        model          = $_.Model.Trim()
        size_gb        = [math]::Round($_.Size / 1GB, 1)
        media_type     = $_.MediaType
        interface_type = $_.InterfaceType
        serial_number  = $_.SerialNumber
        partitions     = [int]$_.Partitions
    }
})

# Display Adapters
$gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object {
    $res = if ($_.CurrentHorizontalResolution -and $_.CurrentVerticalResolution) {
        "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)"
    } else { $null }
    @{
        name           = $_.Name.Trim()
        vram_mb        = if ($_.AdapterRAM) { [int]($_.AdapterRAM / 1MB) } else { $null }
        driver_version = $_.DriverVersion
        resolution     = $res
    }
})

# Printers
$printers = @(Get-CimInstance Win32_Printer | ForEach-Object {
    @{
        name        = $_.Name
        driver_name = $_.DriverName
        is_default  = [bool]$_.Default
        is_network  = [bool]$_.Network
    }
})

# USB Devices (friendly names only, skip root hubs)
$usbDevices = @(Get-PnpDevice -Class USB -Status OK -ErrorAction SilentlyContinue |
    Where-Object { $_.FriendlyName -and $_.FriendlyName -notmatch 'USB Root Hub|Generic USB Hub|Host Controller' } |
    ForEach-Object {
        @{
            name         = $_.FriendlyName
            device_id    = $_.DeviceID
            manufacturer = $_.Manufacturer
        }
    })

# Battery
$batRaw = Get-CimInstance Win32_Battery | Select-Object -First 1
$statusMap = @{ 1='Other'; 2='Unknown'; 3='Fully Charged'; 4='Low'; 5='Critical'; 6='Charging'; 7='Charging and High'; 8='Charging and Low'; 9='Charging and Critical'; 10='Undefined'; 11='Partially Charged' }
$battery = if ($batRaw) {
    @{
        name                     = $batRaw.Name
        design_capacity_mwh      = if ($batRaw.DesignCapacity) { [int]$batRaw.DesignCapacity } else { $null }
        full_charge_capacity_mwh = if ($batRaw.FullChargeCapacity) { [int]$batRaw.FullChargeCapacity } else { $null }
        charge_remaining_pct     = if ($batRaw.EstimatedChargeRemaining) { [int]$batRaw.EstimatedChargeRemaining } else { $null }
        status                   = $statusMap[[int]($batRaw.BatteryStatus)]
    }
} else { $null }

@{
    cpu             = $cpu
    motherboard     = $motherboard
    memory_modules  = $ramModules
    total_ram_gb    = $totalRamGb
    disks           = $disks
    display_adapters = $gpus
    printers        = $printers
    usb_devices     = $usbDevices
    battery         = $battery
} | ConvertTo-Json -Depth 5
