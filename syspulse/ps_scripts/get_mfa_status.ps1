$dsregOutput = dsregcmd /status 2>$null
$azureAdJoined = ($dsregOutput | Select-String "AzureAdJoined\s*:\s*YES") -ne $null
$whfbEnrolled = $false

try {
    # Check if a NGC key container exists for the current user (indicates WHFB enrollment)
    $ngcPath = "$env:LOCALAPPDATA\Microsoft\NGC"
    $whfbEnrolled = (Test-Path $ngcPath) -and ((Get-ChildItem $ngcPath -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)
} catch {}

$localUsers = Get-LocalUser -ErrorAction SilentlyContinue
$noPassword = @()
$neverExpires = @()
if ($localUsers) {
    foreach ($user in ($localUsers | Where-Object { $_.Enabled })) {
        if (-not $user.PasswordRequired) { $noPassword += $user.Name }
        if ($user.PasswordExpires -eq $null) { $neverExpires += $user.Name }
    }
}

@{
    azure_ad_joined = $azureAdJoined
    whfb_enrolled = $whfbEnrolled
    local_accounts_no_password = $noPassword
    password_never_expires = $neverExpires
} | ConvertTo-Json -Depth 5
