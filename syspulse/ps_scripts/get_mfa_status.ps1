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
    # Load DirectoryServices to actually test for blank passwords
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction SilentlyContinue
    $ctx = $null
    try {
        $ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new(
            [System.DirectoryServices.AccountManagement.ContextType]::Machine)
    } catch {}

    foreach ($user in ($localUsers | Where-Object { $_.Enabled })) {
        # Test if account actually accepts a blank password (definitive check)
        $acceptsBlank = $false
        if ($ctx) {
            try { $acceptsBlank = $ctx.ValidateCredentials($user.Name, "") } catch {}
        }
        if ($acceptsBlank) { $noPassword += $user.Name }

        # PasswordNeverExpires is the clean flag (PasswordExpires -eq $null is ambiguous)
        if ($user.PasswordNeverExpires -eq $true) { $neverExpires += $user.Name }
    }
}

@{
    azure_ad_joined = $azureAdJoined
    whfb_enrolled = $whfbEnrolled
    local_accounts_no_password = $noPassword
    password_never_expires = $neverExpires
} | ConvertTo-Json -Depth 5
