# SMBv1
$smb1 = $false
try {
    $smbConf = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    $smb1 = if ($smbConf) { [bool]$smbConf.EnableSMB1Protocol } else { $false }
} catch {}

# Guest account
$guestEnabled = $false
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $guestEnabled = if ($guest) { [bool]$guest.Enabled } else { $false }
} catch {}

# AutoRun
$autorunEnabled = $true
try {
    $autoRunKey = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
    if ($autoRunKey -and $autoRunKey.NoDriveTypeAutoRun -eq 255) { $autorunEnabled = $false }
} catch {}

# RDP
$rdpEnabled = $false
$nlaEnabled = $true
try {
    $rdpKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
    $rdpEnabled = $rdpKey -and $rdpKey.fDenyTSConnections -eq 0
    if ($rdpEnabled) {
        $nlaKey = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
        $nlaEnabled = $nlaKey -and $nlaKey.UserAuthentication -eq 1
    }
} catch {}

# Open shares (exclude admin shares ending with $)
$openShares = @()
try {
    $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\$$' -and $_.Name -ne 'IPC$' }
    $openShares = @($shares | ForEach-Object { $_.Name })
} catch {}

# Secure Boot
$secureBootEnabled = $true
try {
    $secureBootEnabled = [bool](Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
} catch { $secureBootEnabled = $false }

# Password policy
$netAccountsOutput = net accounts 2>$null
$minLength = 0
$complexity = $false
$lockoutThreshold = 0
try {
    $minLengthLine = $netAccountsOutput | Select-String "Minimum password length"
    if ($minLengthLine) { $minLength = [int]($minLengthLine -replace "[^\d]", "") }
    $lockoutLine = $netAccountsOutput | Select-String "Lockout threshold"
    if ($lockoutLine) { $lockoutThreshold = [int]($lockoutLine -replace "[^\d]", "") }

    $secEdit = secedit /export /cfg "$env:TEMP\syspulse_policy.cfg" /quiet 2>$null
    if (Test-Path "$env:TEMP\syspulse_policy.cfg") {
        $policyContent = Get-Content "$env:TEMP\syspulse_policy.cfg" -Raw
        $complexity = $policyContent -match "PasswordComplexity\s*=\s*1"
        Remove-Item "$env:TEMP\syspulse_policy.cfg" -Force -ErrorAction SilentlyContinue
    }
} catch {}

@{
    smb1_enabled = $smb1
    guest_enabled = $guestEnabled
    autorun_enabled = $autorunEnabled
    rdp_enabled = $rdpEnabled
    nla_enabled = $nlaEnabled
    open_shares = $openShares
    secure_boot_enabled = $secureBootEnabled
    weak_password_policy = @{
        min_length = $minLength
        min_length_insufficient = ($minLength -lt 14 -and $minLength -gt 0)
        no_complexity = (-not $complexity)
        no_lockout = ($lockoutThreshold -eq 0)
        lockout_threshold = $lockoutThreshold
    }
} | ConvertTo-Json -Depth 5
