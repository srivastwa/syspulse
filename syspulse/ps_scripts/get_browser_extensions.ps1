# get_browser_extensions.ps1 — Chrome, Edge, Brave, Firefox extension inventory
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

$extensions = [System.Collections.Generic.List[hashtable]]::new()

function Get-ExtensionEnabledState {
    param([string]$ProfileDir, [string]$ExtId)
    # Read Preferences JSON to get per-extension enabled state
    $prefsFile = Join-Path $ProfileDir 'Preferences'
    if (-not (Test-Path $prefsFile)) { return $true }
    try {
        $prefs = Get-Content $prefsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $extState = $prefs.extensions.settings.$ExtId
        if ($null -eq $extState) { return $true }
        # state: 1 = enabled, 0 = disabled
        if ($extState.PSObject.Properties['state']) {
            return ($extState.state -eq 1)
        }
        return $true
    } catch { return $true }
}

function Get-ChromiumExtensions {
    param([string]$Browser, [string]$BaseDir)
    if (-not (Test-Path $BaseDir)) { return }

    # Walk ALL subdirectories — not just Default/Profile N — to catch any profile naming
    Get-ChildItem $BaseDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne 'System Profile' -and $_.Name -ne 'Guest Profile' -and
                       (Test-Path (Join-Path $_.FullName 'Extensions')) } |
        ForEach-Object {
            $profileDir = $_.FullName
            $extRoot = Join-Path $profileDir 'Extensions'

            Get-ChildItem $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extId = $_.Name
                # Skip Chrome/Edge internal component extensions (all digits/underscores)
                if ($extId -match '^[0-9_]+$') { return }

                # Pick newest version directory
                $versionDir = Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
                if (-not $versionDir) { return }

                $manifest = Join-Path $versionDir.FullName 'manifest.json'
                if (-not (Test-Path $manifest)) { return }

                try {
                    $m = Get-Content $manifest -Raw -Encoding UTF8 | ConvertFrom-Json

                    # Resolve localised name (__MSG_xxx__)
                    $extName = if ($m.name -match '^__MSG_') {
                        $msgKey = $m.name -replace '^__MSG_|__$', ''
                        $localesDir = Join-Path $versionDir.FullName '_locales'
                        # Try en first, then en_US, then any locale
                        $msgFile = $null
                        foreach ($locale in @('en', 'en_US', 'en_GB')) {
                            $candidate = Join-Path $localesDir "$locale\messages.json"
                            if (Test-Path $candidate) { $msgFile = $candidate; break }
                        }
                        if (-not $msgFile) {
                            $msgFile = Get-ChildItem $localesDir -Filter 'messages.json' -Recurse `
                                -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
                        }
                        if ($msgFile -and (Test-Path $msgFile)) {
                            $msgs = Get-Content $msgFile -Raw -Encoding UTF8 | ConvertFrom-Json
                            $msgEntry = $msgs.$msgKey
                            if ($msgEntry) { $msgEntry.message } else { $extId }
                        } else { $extId }
                    } else { $m.name }

                    $extName = ($extName -replace '\r?\n', ' ').Trim()
                    if (-not $extName -or $extName -eq '') { $extName = $extId }

                    # Resolve description
                    $desc = if ($m.description -and $m.description -notmatch '^__MSG_') {
                        ($m.description -replace '\r?\n', ' ').Trim()
                    } else { $null }

                    # Check enabled state from Preferences
                    $enabled = Get-ExtensionEnabledState -ProfileDir $profileDir -ExtId $extId

                    $script:extensions.Add(@{
                        browser      = $Browser
                        extension_id = $extId
                        name         = $extName
                        version      = $m.version
                        description  = $desc
                        enabled      = $enabled
                    })
                } catch {}
            }
        }
}

# ── Chromium-based browsers ───────────────────────────────────────────────────
Get-ChromiumExtensions -Browser 'chrome' `
    -BaseDir "$env:LOCALAPPDATA\Google\Chrome\User Data"

Get-ChromiumExtensions -Browser 'edge' `
    -BaseDir "$env:LOCALAPPDATA\Microsoft\Edge\User Data"

Get-ChromiumExtensions -Browser 'brave' `
    -BaseDir "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"

Get-ChromiumExtensions -Browser 'opera' `
    -BaseDir "$env:APPDATA\Opera Software\Opera Stable"

Get-ChromiumExtensions -Browser 'vivaldi' `
    -BaseDir "$env:LOCALAPPDATA\Vivaldi\User Data"

# ── Comet Browser (Arc-like, Chromium-based) ──────────────────────────────────
# Comet stores data under %LOCALAPPDATA%\Comet
Get-ChromiumExtensions -Browser 'comet' `
    -BaseDir "$env:LOCALAPPDATA\Comet\User Data"

# ── Firefox — reads extensions.json from each profile ────────────────────────
$ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
if (Test-Path $ffProfiles) {
    Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $extFile = Join-Path $_.FullName 'extensions.json'
        if (-not (Test-Path $extFile)) { return }
        try {
            $data = Get-Content $extFile -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($addon in $data.addons) {
                if ($addon.type -ne 'extension') { continue }
                $extensions.Add(@{
                    browser      = 'firefox'
                    extension_id = $addon.id
                    name         = $addon.defaultLocale.name
                    version      = $addon.version
                    description  = $addon.defaultLocale.description
                    enabled      = [bool]$addon.active
                })
            }
        } catch {}
    }
}

# ── Deduplicate by browser + extension_id (multiple profiles may overlap) ─────
$seen = [System.Collections.Generic.HashSet[string]]::new()
$deduped = @($extensions | Where-Object {
    $key = "$($_['browser'])|$($_['extension_id'])"
    $seen.Add($key)
})

@{ extensions = $deduped } | ConvertTo-Json -Depth 4
