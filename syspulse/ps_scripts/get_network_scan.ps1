# get_network_scan.ps1 — Discover hosts on local /24 subnets
# Uses async .NET pings (all IPs simultaneously) then port-checks live hosts.
# Outputs a single JSON object to stdout. Exits 0.

$ErrorActionPreference = 'SilentlyContinue'

# ── OUI vendor table (first 3 MAC octets, upper-case colon-separated) ─────────
$ouiMap = @{
    '00:50:56'='VMware';      '00:0C:29'='VMware';       '00:1C:14'='VMware'
    '00:1C:42'='Parallels';   '08:00:27'='VirtualBox';   '52:54:00'='QEMU/KVM'
    'B8:27:EB'='Raspberry Pi';'DC:A6:32'='Raspberry Pi'; 'E4:5F:01'='Raspberry Pi'
    '28:CD:C1'='Apple';       '3C:52:82'='Apple';         'AC:DE:48'='Apple'
    'F0:18:98'='Apple';       '00:1E:C2'='Apple';         'A4:C3:F0'='Intel'
    '5C:F3:70'='Intel';       '00:15:5D'='Microsoft Hyper-V'
    '14:18:77'='Dell';        'F8:DB:88'='Dell';          'D4:BE:D9'='Dell'
    '00:1A:A0'='Dell';        'B0:83:FE'='HP';            '3C:D9:2B'='HP'
    '00:21:5A'='HP';          '00:17:08'='HP';            '00:26:55'='Lenovo'
    'E8:39:35'='Lenovo';      '54:E1:AD'='Lenovo';        '00:1D:60'='ASUS'
    '2C:56:DC'='ASUS';        '04:D9:F5'='ASUS';          '00:E0:4C'='Realtek'
    '00:D0:C9'='TP-Link';     '50:C7:BF'='TP-Link';       'C4:E9:84'='TP-Link'
    '74:DA:38'='Netgear';     'A0:40:A0'='Netgear';       'C4:04:15'='Cisco'
    '00:1A:2B'='Cisco';       'F8:72:EA'='Cisco';         '00:26:B9'='Cisco'
}

function Get-OUIVendor([string]$mac) {
    if (-not $mac) { return $null }
    $normalized = $mac.ToUpper() -replace '-',':'
    if ($normalized.Length -lt 8) { return $null }
    return $ouiMap[$normalized.Substring(0,8)]
}

# ── Find local IPv4 subnets (skip loopback and APIPA) ─────────────────────────
$localAddrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
        $_.PrefixLength -ge 16 -and $_.PrefixLength -le 30
    }

$myIPs   = [System.Collections.Generic.HashSet[string]]::new()
$subnets = [System.Collections.Generic.HashSet[string]]::new()

foreach ($addr in $localAddrs) {
    $myIPs.Add($addr.IPAddress) | Out-Null
    $bytes = [System.Net.IPAddress]::Parse($addr.IPAddress).GetAddressBytes()
    # Scan the /24 regardless of actual prefix — keeps scan bounded to 254 hosts
    $subnets.Add("$($bytes[0]).$($bytes[1]).$($bytes[2])") | Out-Null
}

# ── Build ARP table (IP → MAC) ────────────────────────────────────────────────
$arpTable = @{}
try {
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.State -ne 'Unreachable' -and
                       $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
                       $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } |
        ForEach-Object { $arpTable[$_.IPAddress] = $_.LinkLayerAddress }
} catch {}

$hosts = [System.Collections.Generic.List[hashtable]]::new()

foreach ($subnet in $subnets) {
    $ips = 1..254 | ForEach-Object { "$subnet.$_" }

    # ── Async ping all 254 IPs simultaneously ─────────────────────────────────
    $pingers   = @{}
    $pingTasks = @{}
    foreach ($ip in $ips) {
        $p = New-Object System.Net.NetworkInformation.Ping
        $pingers[$ip]   = $p
        $pingTasks[$ip] = $p.SendPingAsync($ip, 1500)
    }

    # Wait up to 3 seconds for all pings to complete
    $taskArray = @($pingTasks.Values)
    try { [System.Threading.Tasks.Task]::WaitAll($taskArray, 3000) } catch {}

    # Flush ARP cache now (pings will have populated it for live hosts)
    try {
        Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne 'Unreachable' -and
                           $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
                           $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } |
            ForEach-Object {
                if (-not $arpTable.ContainsKey($_.IPAddress)) {
                    $arpTable[$_.IPAddress] = $_.LinkLayerAddress
                }
            }
    } catch {}

    foreach ($ip in $ips) {
        $task = $pingTasks[$ip]
        if (-not $task.IsCompleted) { continue }
        $reply = try { $task.Result } catch { $null }
        if (-not $reply -or $reply.Status -ne [System.Net.NetworkInformation.IPStatus]::Success) { continue }

        $ttl = try { $reply.Options.Ttl } catch { 0 }
        $rtt = $reply.RoundtripTime

        # ── Hostname via reverse DNS ───────────────────────────────────────────
        $hostname = try { [System.Net.Dns]::GetHostEntry($ip).HostName } catch { $null }

        # ── MAC + vendor ───────────────────────────────────────────────────────
        $mac    = $arpTable[$ip]
        $vendor = Get-OUIVendor $mac

        # ── Port checks (300 ms timeout each) — key service fingerprints ───────
        $portDefs = [ordered]@{
            445  = 'SMB'       # Windows file sharing
            3389 = 'RDP'       # Windows Remote Desktop
            5985 = 'WinRM'     # Windows Remote Management
            22   = 'SSH'       # Linux / macOS
            548  = 'AFP'       # macOS file sharing
            5353 = 'mDNS'      # Bonjour (macOS/Linux)
            80   = 'HTTP'
            443  = 'HTTPS'
        }
        $openPorts = [System.Collections.Generic.List[int]]::new()
        $services  = [System.Collections.Generic.List[string]]::new()

        foreach ($port in $portDefs.Keys) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $ar  = $tcp.BeginConnect($ip, $port, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne(300, $false) -and $tcp.Connected) {
                    $openPorts.Add($port)
                    $services.Add($portDefs[$port])
                }
                try { $tcp.Close() } catch {}
            } catch {}
        }

        # ── OS fingerprint: ports (high confidence) then TTL (low) ────────────
        $osGuess      = 'Unknown'
        $osConfidence = 'low'

        if (445 -in $openPorts -or 3389 -in $openPorts -or 5985 -in $openPorts) {
            $osGuess = 'Windows'; $osConfidence = 'high'
        } elseif (548 -in $openPorts) {
            $osGuess = 'macOS'; $osConfidence = 'high'
        } elseif (22 -in $openPorts -and 445 -notin $openPorts) {
            $osGuess = if ($ttl -le 70) { 'Linux' } else { 'Linux/macOS' }
            $osConfidence = 'medium'
        } elseif (5353 -in $openPorts -and 445 -notin $openPorts) {
            $osGuess = 'Linux/macOS'; $osConfidence = 'medium'
        } elseif ($ttl -gt 100 -and $ttl -le 128) {
            $osGuess = 'Windows'; $osConfidence = 'low'
        } elseif ($ttl -gt 0 -and $ttl -le 70) {
            $osGuess = 'Linux/macOS'; $osConfidence = 'low'
        } elseif ($ttl -gt 200) {
            $osGuess = 'Network Device'; $osConfidence = 'medium'
        }

        # macOS via vendor even without AFP open
        if ($osGuess -eq 'Unknown' -and $vendor -eq 'Apple') {
            $osGuess = 'macOS'; $osConfidence = 'low'
        }

        $hosts.Add(@{
            ip               = $ip
            hostname         = $hostname
            mac_address      = $mac
            vendor           = $vendor
            os_guess         = $osGuess
            os_confidence    = $osConfidence
            open_ports       = @($openPorts)
            services         = @($services)
            is_local         = $myIPs.Contains($ip)
            response_time_ms = [int]$rtt
            ttl              = $ttl
        })
    }
}

@{ hosts = @($hosts | Sort-Object { [version]$_['ip'] }) } | ConvertTo-Json -Depth 4
