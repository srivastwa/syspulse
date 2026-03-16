$volumes = @()
try {
    $blVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($blVolumes) {
        $volumes = @($blVolumes | ForEach-Object {
            @{
                mount_point = $_.MountPoint
                protection_status = $_.ProtectionStatus.ToString()
                protection_on = ($_.ProtectionStatus -eq "On")
                encryption_percentage = $_.EncryptionPercentage
                key_protectors = @($_.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
            }
        })
    }
} catch {
    # Fallback: use manage-bde output parsing is complex; report no data
}

@{
    volumes = $volumes
} | ConvertTo-Json -Depth 5
