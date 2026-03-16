$volumes = @()
try {
    $blVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($blVolumes) {
        $volumes = @($blVolumes | ForEach-Object {
            $vol = $_
            # Resolve a human-friendly label for the volume
            $label = try {
                $drv = Get-PSDrive -Name $vol.MountPoint.TrimEnd(':\') -ErrorAction SilentlyContinue
                if ($drv -and $drv.Description) { $drv.Description }
                else {
                    $wmi = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($vol.MountPoint.TrimEnd('\'))'" -ErrorAction SilentlyContinue
                    if ($wmi -and $wmi.VolumeName) { $wmi.VolumeName } else { $null }
                }
            } catch { $null }

            @{
                mount_point         = $vol.MountPoint
                volume_label        = $label
                protection_status   = $vol.ProtectionStatus.ToString()
                # True only if protection is On AND encryption is fully complete
                protection_on       = ($vol.ProtectionStatus -eq "On") -and ($vol.EncryptionPercentage -eq 100)
                volume_status       = $vol.VolumeStatus.ToString()
                encryption_percentage = $vol.EncryptionPercentage
                key_protectors      = @($vol.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() })
            }
        })
    }
} catch {
    # BitLocker cmdlet not available or no volumes
}

@{
    volumes = $volumes
} | ConvertTo-Json -Depth 5
