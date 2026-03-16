$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$pendingUpdates = @()
$daysSinceLast = $null

try {
    $result = $searcher.Search("IsInstalled=0 and Type='Software'")
    $pendingUpdates = @($result.Updates | ForEach-Object {
        @{
            title = $_.Title
            is_security = ($_.Categories | Where-Object { $_.Name -match "Security" } | Measure-Object).Count -gt 0
            kb_ids = @($_.KBArticleIDs)
            severity = if ($_.MsrcSeverity) { $_.MsrcSeverity } else { "Unknown" }
        }
    })
} catch {}

try {
    $historyCount = $searcher.GetTotalHistoryCount()
    if ($historyCount -gt 0) {
        $history = $searcher.QueryHistory(0, 1)
        $lastInstall = $history | Select-Object -First 1
        if ($lastInstall.Date) {
            $daysSinceLast = [int]([datetime]::UtcNow - $lastInstall.Date.ToUniversalTime()).TotalDays
        }
    }
} catch {}

@{
    pending_updates = $pendingUpdates
    pending_count = $pendingUpdates.Count
    days_since_last_install = $daysSinceLast
} | ConvertTo-Json -Depth 5
