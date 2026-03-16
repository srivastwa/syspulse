$members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$admins = @()
if ($members) {
    $admins = @($members | ForEach-Object {
        $user = $null
        try {
            $user = Get-LocalUser -Name $_.Name.Split('\')[-1] -ErrorAction SilentlyContinue
        } catch {}
        @{
            name = $_.Name.Split('\')[-1]
            full_name = $_.Name
            object_class = $_.ObjectClass
            enabled = if ($user) { [bool]$user.Enabled } else { $true }
            principal_source = $_.PrincipalSource.ToString()
        }
    })
}

@{
    local_admins = $admins
    total_count = $admins.Count
} | ConvertTo-Json -Depth 5
