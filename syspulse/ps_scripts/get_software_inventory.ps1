# get_software_inventory.ps1 — Installed software and Windows product ID
# Outputs a single JSON object to stdout. Exits 0 on success.

$ErrorActionPreference = 'SilentlyContinue'

$seen     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$software = [System.Collections.Generic.List[hashtable]]::new()

# ── 1. Registry Uninstall keys (HKLM 64-bit, HKLM 32-bit, HKCU) ─────────────
$regPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

foreach ($path in $regPaths) {
    if (-not (Test-Path $path)) { continue }
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne '' -and $_.SystemComponent -ne 1 } |
        ForEach-Object {
            $key = $_.DisplayName.Trim()
            if ($seen.Add($key)) {
                $idate = $_.InstallDate
                if ($idate -match '^\d{8}$') {
                    $idate = "$($idate.Substring(0,4))-$($idate.Substring(4,2))-$($idate.Substring(6,2))"
                }
                $software.Add(@{
                    name         = $_.DisplayName.Trim()
                    version      = $_.DisplayVersion
                    publisher    = $_.Publisher
                    install_date = $idate
                    source       = 'registry'
                })
            }
        }
}

# ── 2. Python installs via Python-specific registry keys ──────────────────────
foreach ($hive in @('HKLM:\SOFTWARE\Python\PythonCore', 'HKCU:\Software\Python\PythonCore')) {
    if (-not (Test-Path $hive)) { continue }
    Get-ChildItem $hive -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = $_.PSChildName
        $installPath = (Get-ItemProperty "$($_.PSPath)\InstallPath" -ErrorAction SilentlyContinue).'(default)'
        $name = "Python $ver"
        if ($seen.Add($name)) {
            $software.Add(@{
                name         = $name
                version      = $ver
                publisher    = 'Python Software Foundation'
                install_date = $null
                source       = 'python-registry'
            })
        }
    }
}

# ── 3. Windows Store / AppX packages ─────────────────────────────────────────
try {
    # Exclude Microsoft system/runtime packages — only keep user-installed Store apps
    $msSystemPattern = '^Microsoft\.(Windows|VCLibs|NET|DirectX|Gaming|MicrosoftEdge|AAD|Advertising|' +
        'BingWeather|CredDialogHost|CryptoWinRT|DesktopAppInstaller|ECApp|GamingApp|GetHelp|' +
        'HEIFImageExtension|Messaging|MixedReality|MoCamera|MSPaint|Narraton|Office|OneDriveSync|' +
        'OneNote|Paint|People|ScreenSketch|SecHealthUI|Services|SkypeApp|StorePurchaseApp|' +
        'Todos|UI\.Xaml|VP9|WebMediaExtensions|WebpImageExtension|Win32WebViewHost|' +
        'Windows\.Photos|WindowsAlarms|WindowsCalculator|WindowsCamera|WindowsMaps|' +
        'WindowsNotepad|WindowsSoundRecorder|WindowsTerminal|Xbox|YourPhone|ZuneMusic|ZuneVideo)'
    $skipPublishers = @('Microsoft Corporation', 'CN=Microsoft Corporation')

    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
        Where-Object {
            $_.SignatureKind -ne 'System' -and
            $_.Name -notmatch $msSystemPattern -and
            # Skip packages whose internal name is a GUID-like framework package
            $_.Name -notmatch '^[0-9A-Fa-f]{8}-'
        } |
        ForEach-Object {
            # Use display name from manifest if available, else package name
            $displayName = try {
                (Get-AppxPackageManifest $_ -ErrorAction SilentlyContinue).Package.Properties.DisplayName
            } catch { $null }
            if (-not $displayName -or $displayName -match '^\s*$' -or $displayName -match '^ms-resource:') {
                $displayName = $_.Name
            }
            $displayName = $displayName.Trim()
            # Skip if display name still looks like a package ID or is blank
            if (-not $displayName -or $displayName -match '^[A-Za-z0-9]{32}$') { return }

            if ($seen.Add($displayName)) {
                $software.Add(@{
                    name         = $displayName
                    version      = $_.Version
                    publisher    = $_.PublisherDisplayName
                    install_date = $null
                    source       = 'appx'
                })
            }
        }
} catch {}

# ── 4. Electron apps in %LOCALAPPDATA%\Programs\ (VS Code, Cursor, Postman…) ─
$localPrograms = "$env:LOCALAPPDATA\Programs"
if (Test-Path $localPrograms) {
    Get-ChildItem $localPrograms -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $appDir = $_.FullName

        # Try resources\app\package.json (standard Electron layout)
        $pkgJson = $null
        foreach ($candidate in @(
            (Join-Path $appDir 'resources\app\package.json'),
            (Join-Path $appDir 'resources\app.asar.unpacked\package.json')
        )) {
            if (Test-Path $candidate) { $pkgJson = $candidate; break }
        }

        if ($pkgJson) {
            try {
                $pkg = Get-Content $pkgJson -Raw -Encoding UTF8 | ConvertFrom-Json
                $name = if ($pkg.productName) { $pkg.productName } elseif ($pkg.name) { $pkg.name } else { $_.Name }
                $name = $name.Trim()
                if ($seen.Add($name)) {
                    $software.Add(@{
                        name         = $name
                        version      = $pkg.version
                        publisher    = if ($pkg.author) { if ($pkg.author -is [string]) { $pkg.author } else { $pkg.author.name } } else { $null }
                        install_date = $null
                        source       = 'electron-local'
                    })
                }
            } catch {}
        } else {
            # Fallback: look for a single .exe whose name matches the folder name
            $exe = Get-ChildItem $appDir -Filter '*.exe' -ErrorAction SilentlyContinue |
                Where-Object { $_.BaseName -notmatch -join('Update','Squirrel','unins') } |
                Select-Object -First 1
            if ($exe) {
                $vi = $exe.VersionInfo
                $name = if ($vi.ProductName -and $vi.ProductName.Trim()) { $vi.ProductName.Trim() } else { $_.Name }
                if ($seen.Add($name)) {
                    $ver = if ($vi.ProductVersion) { $vi.ProductVersion } else { $null }
                    $software.Add(@{
                        name         = $name
                        version      = $ver
                        publisher    = if ($vi.CompanyName) { $vi.CompanyName.Trim() } else { $null }
                        install_date = $null
                        source       = 'local-programs'
                    })
                }
            }
        }
    }
}

# ── 5. MongoDB — check service + Program Files ────────────────────────────────
if (-not ($seen -contains 'MongoDB')) {
    $mongoService = Get-Service -Name 'MongoDB' -ErrorAction SilentlyContinue
    if ($mongoService) {
        $mongoBin = (Get-WmiObject Win32_Service -Filter "Name='MongoDB'" -ErrorAction SilentlyContinue).PathName
        $ver = $null
        if ($mongoBin) {
            $exePath = $mongoBin -replace '"',''.Trim()
            $vi = (Get-Item $exePath -ErrorAction SilentlyContinue).VersionInfo
            $ver = $vi.ProductVersion
        }
        if ($seen.Add('MongoDB')) {
            $software.Add(@{
                name         = 'MongoDB'
                version      = $ver
                publisher    = 'MongoDB, Inc.'
                install_date = $null
                source       = 'service'
            })
        }
    }
}

# ── 6. Winget (if available) — catches anything still missing ─────────────────
try {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        $wgOut = winget list --accept-source-agreements 2>$null
        # Parse the tabular output: skip header lines until dashes row, then parse entries.
        # Winget emits Unicode progress-bar characters (block elements U+2580-U+259F, U+25A0-U+25FF)
        # to stdout — filter those lines out before parsing.
        $inData = $false
        foreach ($line in ($wgOut -split "`n")) {
            # Skip winget progress/spinner lines (contain Unicode block-drawing chars)
            if ($line -match '[\u2500-\u259F\u25A0-\u25FF\u2800-\u28FF]') { continue }
            if ($line -match '^[-\s]+$') { $inData = $true; continue }
            if (-not $inData) { continue }
            $line = $line.Trim()
            if ($line -eq '') { continue }
            # Columns: Name, Id, Version, Available, Source  (fixed-width)
            # Grab Name = first column (up to two or more spaces)
            if ($line -match '^(.+?)\s{2,}') {
                $name = $Matches[1].Trim()
                # Skip if name still contains non-printable or box-drawing characters
                if ($name -match '[^\x20-\x7E]') { continue }
                if ($name -and $seen.Add($name)) {
                    $software.Add(@{
                        name         = $name
                        version      = $null
                        publisher    = $null
                        install_date = $null
                        source       = 'winget'
                    })
                }
            }
        }
    }
} catch {}

# ── Sort and output ───────────────────────────────────────────────────────────
$sorted = @($software | Sort-Object { $_['name'] })

$winProductId = try {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductId
} catch { $null }

@{
    software           = $sorted
    windows_product_id = $winProductId
} | ConvertTo-Json -Depth 3
