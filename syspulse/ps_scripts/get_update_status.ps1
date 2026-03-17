# get_update_status.ps1 — Windows Update pending patches and last install date
# Outputs a single JSON object to stdout. Exits 0 on success.
#
# The WUA COM searcher can take 60-120s on corporate/WSUS machines because it
# contacts the update server. We run it in a background job with a 90-second
# timeout so the overall script always returns within ~100 seconds.

$ErrorActionPreference = 'SilentlyContinue'

$pendingUpdates  = @()
$daysSinceLast   = $null
$searchTimedOut  = $false

# ── 1. Fast path: last install date via WUA history (local, no network) ───────
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    if ($historyCount -gt 0) {
        $history = $searcher.QueryHistory(0, 1)
        $last    = $history | Select-Object -First 1
        if ($last.Date) {
            $daysSinceLast = [int]([datetime]::UtcNow - $last.Date.ToUniversalTime()).TotalDays
        }
    }
} catch {}

# ── 2. Check registry for "reboot required" and cached pending count ──────────
$rebootRequired = $false
$wuRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
if (Test-Path $wuRegPath) { $rebootRequired = $true }

# Cached pending update count from orchestrator (avoids live search in most cases)
$cachedPending = $null
try {
    $cachedPending = (Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' `
        -ErrorAction SilentlyContinue).AUOptions
} catch {}

# ── 3. Slow path: live WUA search in a background job with 90-second cap ──────
$job = Start-Job -ScriptBlock {
    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $result   = $searcher.Search("IsInstalled=0 and Type='Software'")
        $updates  = @($result.Updates | ForEach-Object {
            @{
                title       = $_.Title
                is_security = (($_.Categories |
                    Where-Object { $_.Name -match 'Security' } |
                    Measure-Object).Count -gt 0)
                kb_ids      = @($_.KBArticleIDs)
                severity    = if ($_.MsrcSeverity) { $_.MsrcSeverity } else { 'Unknown' }
            }
        })
        $updates
    } catch {
        @()
    }
}

$completed = Wait-Job $job -Timeout 90
if ($completed) {
    $pendingUpdates = @(Receive-Job $job)
} else {
    Stop-Job $job
    $searchTimedOut = $true
}
Remove-Job $job -Force -ErrorAction SilentlyContinue

# ── 4. Fallback: use Get-HotFix for last patch date if WUA history failed ─────
if ($null -eq $daysSinceLast) {
    try {
        $lastHotfix = Get-HotFix | Sort-Object InstalledOn -Descending |
            Select-Object -First 1
        if ($lastHotfix.InstalledOn) {
            $daysSinceLast = [int]([datetime]::UtcNow - $lastHotfix.InstalledOn.ToUniversalTime()).TotalDays
        }
    } catch {}
}

@{
    pending_updates        = $pendingUpdates
    pending_count          = $pendingUpdates.Count
    days_since_last_install = $daysSinceLast
    reboot_required        = $rebootRequired
    search_timed_out       = $searchTimedOut
} | ConvertTo-Json -Depth 5
