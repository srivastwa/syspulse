# get_software_inventory.ps1 — Installed software and Windows product ID
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

$regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$seen   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$software = [System.Collections.Generic.List[hashtable]]::new()

foreach ($path in $regPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' -and $_.SystemComponent -ne 1 } |
        ForEach-Object {
            $key = "$($_.DisplayName)|$($_.DisplayVersion)"
            if ($seen.Add($key)) {
                # Normalise install date YYYYMMDD → YYYY-MM-DD
                $idate = $_.InstallDate
                if ($idate -match '^\d{8}$') {
                    $idate = "$($idate.Substring(0,4))-$($idate.Substring(4,2))-$($idate.Substring(6,2))"
                }
                $software.Add(@{
                    name             = $_.DisplayName.Trim()
                    version          = $_.DisplayVersion
                    publisher        = $_.Publisher
                    install_date     = $idate
                    install_location = $_.InstallLocation
                })
            }
        }
}

# Sort by name
$sorted = @($software | Sort-Object { $_['name'] })

# Windows product ID (not the retail key — just the ID for identification)
$winProductId = try {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductId
} catch { $null }

@{
    software           = $sorted
    windows_product_id = $winProductId
} | ConvertTo-Json -Depth 3
