$profiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
@{
    profiles = @($profiles | ForEach-Object {
        @{
            name = $_.Name
            enabled = [bool]$_.Enabled
            default_inbound = $_.DefaultInboundAction.ToString()
            default_outbound = $_.DefaultOutboundAction.ToString()
        }
    })
} | ConvertTo-Json -Depth 5
