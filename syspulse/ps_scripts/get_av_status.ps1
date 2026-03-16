$providers = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
$defenderStatus = $null
try {
    $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mpStatus) {
        $defenderStatus = @{
            realtime_enabled = [bool]$mpStatus.RealTimeProtectionEnabled
            signatures_last_updated = $mpStatus.AntivirusSignatureLastUpdated.ToUniversalTime().ToString("o")
            antivirus_enabled = [bool]$mpStatus.AntivirusEnabled
        }
    }
} catch {}

@{
    providers = @($providers | ForEach-Object {
        @{
            displayName = $_.displayName
            productState = $_.productState
        }
    })
    signatures_last_updated = if ($defenderStatus) { $defenderStatus.signatures_last_updated } else { $null }
    realtime_enabled = if ($defenderStatus) { $defenderStatus.realtime_enabled } else { $null }
} | ConvertTo-Json -Depth 5
