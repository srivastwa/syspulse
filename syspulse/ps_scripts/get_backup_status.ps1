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
$backupSoftware = @("Veeam", "Acronis", "Backup Exec", "Carbonite", "Backblaze")
foreach ($sw in $backupSoftware) {
    $installed = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match $sw }
    if ($installed) { $thirdParty += $sw }
}

@{
    file_history_enabled = $fileHistoryEnabled
    vss_snapshot_count = $vssCount
    wbadmin_present = $wbadminPresent
    third_party_backup = $thirdParty
} | ConvertTo-Json -Depth 5
