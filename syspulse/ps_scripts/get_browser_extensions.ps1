# get_browser_extensions.ps1 — Chrome, Edge, Firefox extension inventory
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

$extensions = [System.Collections.Generic.List[hashtable]]::new()

function Get-ChromiumExtensions {
    param([string]$Browser, [string]$BaseDir)
    if (-not (Test-Path $BaseDir)) { return }
    # Walk all profile dirs (Default, Profile 1, etc.)
    Get-ChildItem $BaseDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Default|Profile \d+)$' } |
        ForEach-Object {
            $extRoot = Join-Path $_.FullName 'Extensions'
            if (-not (Test-Path $extRoot)) { return }
            Get-ChildItem $extRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extId = $_.Name
                # Each extension has version sub-directories; pick the newest
                $versionDir = Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue |
                    Sort-Object Name -Descending | Select-Object -First 1
                if (-not $versionDir) { return }
                $manifest = Join-Path $versionDir.FullName 'manifest.json'
                if (-not (Test-Path $manifest)) { return }
                try {
                    $m = Get-Content $manifest -Raw -Encoding UTF8 | ConvertFrom-Json
                    $extName = if ($m.name -match '^__MSG_') {
                        # Localised name — try to find _locales/en/messages.json
                        $msgKey = $m.name -replace '^__MSG_|__$', ''
                        $msgFile = Join-Path $versionDir.FullName "_locales\en\messages.json"
                        if (-not (Test-Path $msgFile)) {
                            $msgFile = Get-ChildItem (Join-Path $versionDir.FullName '_locales') `
                                -Filter 'messages.json' -Recurse -ErrorAction SilentlyContinue |
                                Select-Object -First 1 -ExpandProperty FullName
                        }
                        if ($msgFile -and (Test-Path $msgFile)) {
                            $msgs = Get-Content $msgFile -Raw -Encoding UTF8 | ConvertFrom-Json
                            $msg  = $msgs.$msgKey
                            if ($msg) { $msg.message } else { $extId }
                        } else { $extId }
                    } else { $m.name }

                    $script:extensions.Add(@{
                        browser      = $Browser
                        extension_id = $extId
                        name         = ($extName -replace '\r?\n', ' ').Trim()
                        version      = $m.version
                        description  = if ($m.description -and $m.description -notmatch '^__MSG_') {
                            ($m.description -replace '\r?\n', ' ').Trim()
                        } else { $null }
                        enabled      = $true
                    })
                } catch {}
            }
        }
}

# Chrome
Get-ChromiumExtensions -Browser 'chrome' `
    -BaseDir "$env:LOCALAPPDATA\Google\Chrome\User Data"

# Edge (Chromium)
Get-ChromiumExtensions -Browser 'edge' `
    -BaseDir "$env:LOCALAPPDATA\Microsoft\Edge\User Data"

# Brave
Get-ChromiumExtensions -Browser 'brave' `
    -BaseDir "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"

# Firefox — reads extensions.json from each profile
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

# Deduplicate by browser+id (multiple profiles may have the same extension)
$seen = [System.Collections.Generic.HashSet[string]]::new()
$deduped = @($extensions | Where-Object {
    $key = "$($_['browser'])|$($_['extension_id'])"
    $seen.Add($key)
})

@{ extensions = $deduped } | ConvertTo-Json -Depth 4
