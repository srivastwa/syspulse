# get_network_inventory.ps1 — Network adapters, shares, mapped drives, local users
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

# Network adapters with IP addresses
$adapters = @(Get-NetAdapter | ForEach-Object {
    $iface = $_
    $ips = @(Get-NetIPAddress -InterfaceIndex $iface.InterfaceIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.AddressFamily -in 'IPv4', 'IPv6' } |
        Select-Object -ExpandProperty IPAddress)
    $speedMbps = if ($iface.LinkSpeed -and $iface.LinkSpeed -gt 0) {
        [int]($iface.LinkSpeed / 1000000)
    } else { $null }
    @{
        name        = $iface.Name
        description = $iface.InterfaceDescription
        mac_address = $iface.MacAddress
        ip_addresses = $ips
        speed_mbps  = $speedMbps
        status      = $iface.Status.ToString()
    }
})

# Shared folders (exclude hidden admin shares ending in $)
$shares = @(Get-SmbShare -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '\$$' } |
    ForEach-Object {
        @{
            name        = $_.Name
            path        = $_.Path
            description = $_.Description
        }
    })

# Mapped drives
$mapped = @(Get-SmbMapping -ErrorAction SilentlyContinue |
    ForEach-Object {
        @{
            drive_letter = $_.LocalPath
            remote_path  = $_.RemotePath
        }
    })

# Local user accounts with group membership
$users = @(Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
    $uname = $_.Name
    $groups = @(Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
        $grp = $_
        $members = Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue
        if ($members | Where-Object { $_.Name -match "\\$uname$" -or $_.Name -eq $uname }) {
            $grp.Name
        }
    })
    @{
        name              = $_.Name
        full_name         = $_.FullName
        enabled           = [bool]$_.Enabled
        last_logon        = if ($_.LastLogon) { $_.LastLogon.ToString('o') } else { $null }
        password_required = [bool]$_.PasswordRequired
        password_expires  = -not [bool]$_.PasswordNeverExpires
        groups            = $groups
    }
})

@{
    network_adapters = $adapters
    shared_folders   = $shares
    mapped_drives    = $mapped
    user_accounts    = $users
} | ConvertTo-Json -Depth 4
