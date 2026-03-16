$fileHistoryEnabled = $false
try {
    $fhKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory" -ErrorAction SilentlyContinue
    $fileHistoryEnabled = $fhKey -and $fhKey.Enabled -eq 1
} catch {}

$vssCount = 0
try {
    $shadows = vssadmin list shadows 2>$null
    $vssCount = ([regex]::Matches($shadows, "Shadow Copy ID:")).Count
} catch {}

$wbadminPresent = $false
try {
    $wbadminPresent = (Get-Command wbadmin -ErrorAction SilentlyContinue) -ne $null
} catch {}

$thirdParty = @()
$backupKeywords = @("Veeam", "Acronis", "Backup Exec", "Carbonite", "Backblaze", "Macrium", "AOMEI", "EaseUS.*Backup", "Cobian", "Duplicati")
$regPaths = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
foreach ($keyword in $backupKeywords) {
    foreach ($path in $regPaths) {
        $found = Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match $keyword }
        if ($found) {
            # Store the actual product DisplayName, not the keyword
            $thirdParty += ($found | Select-Object -First 1).DisplayName
            break
        }
    }
}

@{
    file_history_enabled = $fileHistoryEnabled
    vss_snapshot_count = $vssCount
    wbadmin_present = $wbadminPresent
    third_party_backup = $thirdParty
} | ConvertTo-Json -Depth 5
