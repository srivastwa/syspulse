# get_browser_extensions.ps1 — Chrome, Edge, Brave, Firefox extension inventory
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

$extensions = [System.Collections.Generic.List[hashtable]]::new()

function Get-ProfileInfo {
    param([string]$ProfileDir, [string]$FolderName)
    # Read Preferences JSON to get the human-readable profile name
    $prefsFile = Join-Path $ProfileDir 'Preferences'
    if (-not (Test-Path $prefsFile)) { return $FolderName }
    try {
        $prefs = Get-Content $prefsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $displayName = $prefs.profile.name
        if ($displayName -and $displayName.Trim() -ne '') { return $displayName.Trim() }
    } catch {}
    return $FolderName
}

function Get-ExtensionEnabledState {
    param([string]$ProfileDir, [string]$ExtId)
    $prefsFile = Join-Path $ProfileDir 'Preferences'
    if (-not (Test-Path $prefsFile)) { return $true }
    try {
        $prefs = Get-Content $prefsFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $extState = $prefs.extensions.settings.$ExtId
        if ($null -eq $extState) { return $true }
        if ($extState.PSObject.Properties['state']) { return ($extState.state -eq 1) }
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
            $profileDir  = $_.FullName
            $profileName = Get-ProfileInfo -ProfileDir $profileDir -FolderName $_.Name
            $extRoot     = Join-Path $profileDir 'Extensions'

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
                        profile      = $profileName
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

# ── Enumerate all Windows user profile directories ────────────────────────────
# Scan the current user first, then every other user profile we can read.
$userRoots = [System.Collections.Generic.List[hashtable]]::new()

# Current user (always accessible)
$userRoots.Add(@{ User = $env:USERNAME; LocalAppData = $env:LOCALAPPDATA; AppData = $env:APPDATA })

# Other user accounts — iterate C:\Users\*
$usersDir = "$env:SystemDrive\Users"
if (Test-Path $usersDir) {
    Get-ChildItem $usersDir -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ne $env:USERNAME -and $_.Name -ne 'Public' -and $_.Name -ne 'Default' -and $_.Name -ne 'Default User' -and $_.Name -ne 'All Users' } |
        ForEach-Object {
            $otherLocal = Join-Path $_.FullName 'AppData\Local'
            $otherRoaming = Join-Path $_.FullName 'AppData\Roaming'
            if ((Test-Path $otherLocal) -or (Test-Path $otherRoaming)) {
                $userRoots.Add(@{ User = $_.Name; LocalAppData = $otherLocal; AppData = $otherRoaming })
            }
        }
}

# ── Chromium-based browsers ───────────────────────────────────────────────────
# Browser definitions: name → relative path under LocalAppData or AppData
$chromiumBrowsers = @(
    @{ Browser = 'chrome';  RelPath = 'Google\Chrome\User Data';               Root = 'local' }
    @{ Browser = 'edge';    RelPath = 'Microsoft\Edge\User Data';              Root = 'local' }
    @{ Browser = 'brave';   RelPath = 'BraveSoftware\Brave-Browser\User Data'; Root = 'local' }
    @{ Browser = 'opera';   RelPath = 'Opera Software\Opera Stable';           Root = 'roaming' }
    @{ Browser = 'vivaldi'; RelPath = 'Vivaldi\User Data';                     Root = 'local' }
    @{ Browser = 'comet';   RelPath = 'Comet\User Data';                       Root = 'local' }
)

foreach ($ur in $userRoots) {
    $userName = $ur.User

    foreach ($bDef in $chromiumBrowsers) {
        $parentDir = if ($bDef.Root -eq 'roaming') { $ur.AppData } else { $ur.LocalAppData }
        $baseDir = Join-Path $parentDir $bDef.RelPath
        $browserLabel = if ($userName -ne $env:USERNAME) { "$($bDef.Browser) ($userName)" } else { $bDef.Browser }
        Get-ChromiumExtensions -Browser $browserLabel -BaseDir $baseDir
    }

    # ── Firefox — reads extensions.json from each profile ────────────────────
    $ffProfiles = Join-Path $ur.AppData 'Mozilla\Firefox\Profiles'
    $ffIniPath  = Join-Path $ur.AppData 'Mozilla\Firefox\profiles.ini'
    $browserLabel = if ($userName -ne $env:USERNAME) { "firefox ($userName)" } else { 'firefox' }

    if (Test-Path $ffProfiles) {
        Get-ChildItem $ffProfiles -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $extFile = Join-Path $_.FullName 'extensions.json'
            if (-not (Test-Path $extFile)) { return }
            try {
                $data = Get-Content $extFile -Raw -Encoding UTF8 | ConvertFrom-Json
                $ffProfileName = try {
                    $profileIni = Get-Content $ffIniPath -Raw -ErrorAction SilentlyContinue
                    $folderName = $_.Name
                    if ($profileIni -and $profileIni -match "(?s)Path=Profiles/$([regex]::Escape($folderName)).*?Name=([^\r\n]+)") {
                        $Matches[1].Trim()
                    } else { $folderName }
                } catch { $_.Name }

                foreach ($addon in $data.addons) {
                    if ($addon.type -ne 'extension') { continue }
                    $extensions.Add(@{
                        browser      = $browserLabel
                        profile      = $ffProfileName
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
}

# ── Deduplicate by browser + profile + extension_id ───────────────────────────
$seen = [System.Collections.Generic.HashSet[string]]::new()
$deduped = @($extensions | Where-Object {
    $key = "$($_['browser'])|$($_['profile'])|$($_['extension_id'])"
    $seen.Add($key)
})

@{ extensions = $deduped } | ConvertTo-Json -Depth 4
