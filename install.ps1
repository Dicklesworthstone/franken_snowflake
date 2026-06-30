<#
.SYNOPSIS
    Installer for the franken-snowflake CLI on Windows (binaries: franken-snowflake.exe + short alias fsnow.exe).

.DESCRIPTION
    franken-snowflake is a clean-room, Asupersync-native Snowflake SQL API
    connector built for coding agents. This script installs the agent-ergonomic
    CLI tool (not the library).

    One-liner install:
        irm https://raw.githubusercontent.com/Dicklesworthstone/franken_snowflake/main/install.ps1 | iex

    To pass parameters, download then invoke:
        irm https://raw.githubusercontent.com/Dicklesworthstone/franken_snowflake/main/install.ps1 -OutFile install.ps1
        ./install.ps1 -EasyMode -Verify

    Release binaries:
        The normal installer path downloads prepared GitHub release archives
        named franken-snowflake-vX.Y.Z-<target-triple>.zip. This installer never
        builds from source automatically. If no release or no matching platform
        archive exists, it fails with the exact missing asset. -FromSource is an
        explicit developer escape hatch only.

    The installed binary can also serve Model Context Protocol:
        franken-snowflake mcp serve --stdio

.PARAMETER Version
    Install a specific released version (default: latest). Example: v0.1.0

.PARAMETER Dest
    Install directory. Default: $env:USERPROFILE\.local\bin

.PARAMETER System
    Install for all users into "$env:ProgramFiles\franken-snowflake" (needs admin).

.PARAMETER EasyMode
    Add the install directory to the User PATH and auto-install Rust if missing.

.PARAMETER Verify
    Run a post-install self-test (selftest + capabilities) after installing.

.PARAMETER FromSource
    Developer-only: build from source with cargo instead of downloading a
    prepared release binary.

.PARAMETER Live
    Build the CLI with the 'live' feature (real Snowflake SQL API transport).
    Applies only to -FromSource. Release binaries already include the published
    feature set.

.PARAMETER Offline
    Install from a local artifact archive (.zip/.tar.*) instead of downloading.

.PARAMETER ArtifactUrl
    Download the artifact from an explicit URL.

.PARAMETER Checksum
    Expected SHA256 of the artifact (overrides a remote SHA256SUMS file).

.PARAMETER ChecksumUrl
    URL of a SHA256SUMS file to verify the artifact against.

.PARAMETER NoVerify
    Skip checksum verification (NOT recommended).

.PARAMETER Quiet
    Suppress non-error output.

.PARAMETER Force
    Reinstall even if the same version is already present.

.EXAMPLE
    ./install.ps1
    Install the latest franken-snowflake into %USERPROFILE%\.local\bin.

.EXAMPLE
    ./install.ps1 -EasyMode -Verify
    Install, add to PATH, and run the self-test.

.EXAMPLE
    ./install.ps1 -FromSource
    Build franken-snowflake.exe + fsnow.exe from source with cargo.

.EXAMPLE
    ./install.ps1 -FromSource -Live
    Build the live-capable CLI from source with cargo.

.NOTES
    Passing parameters through the one-liner: the `irm ... | iex` form cannot take
    arguments directly. Download first, then invoke with the switch, e.g.:
        irm https://raw.githubusercontent.com/Dicklesworthstone/franken_snowflake/main/install.ps1 -OutFile install.ps1
        ./install.ps1 -FromSource -Live
    Or wrap it inline:
        & ([scriptblock]::Create((irm https://raw.githubusercontent.com/Dicklesworthstone/franken_snowflake/main/install.ps1))) -FromSource -Live
#>

[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$Dest = "$env:USERPROFILE\.local\bin",
    [switch]$System,
    [switch]$EasyMode,
    [switch]$Verify,
    [switch]$FromSource,
    [switch]$Live,
    [string]$Offline = "",
    [string]$ArtifactUrl = "",
    [string]$Checksum = "",
    [string]$ChecksumUrl = "",
    [switch]$NoVerify,
    [switch]$Quiet,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ── Configuration ───────────────────────────────────────────────────────────
$Owner       = 'Dicklesworthstone'
$Repo        = 'franken_snowflake'
$BinaryName  = 'franken-snowflake'
$AliasName   = 'fsnow'
$CliPackage  = 'franken-snowflake-cli'

$script:NoRelease  = $false
$script:VersionBare = ''
$script:Tmp = $null

if ($System) {
    $Dest = Join-Path $env:ProgramFiles 'franken-snowflake'
}

# ── Output helpers ──────────────────────────────────────────────────────────
function Write-Info { param([string]$Msg) if (-not $Quiet) { Write-Host "-> $Msg" -ForegroundColor Cyan } }
function Write-Ok   { param([string]$Msg) if (-not $Quiet) { Write-Host "OK $Msg" -ForegroundColor Green } }
function Write-Warn { param([string]$Msg) Write-Host "!  $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "x  $Msg" -ForegroundColor Red }

function Write-Header {
    if ($Quiet) { return }
    $line = ('=' * 62)
    Write-Host ''
    Write-Host "  +$line+" -ForegroundColor Cyan
    Write-Host "  | franken-snowflake installer" -ForegroundColor Green -NoNewline
    Write-Host (' ' * 33) -NoNewline; Write-Host '|' -ForegroundColor Cyan
    Write-Host "  | Asupersync-native Snowflake SQL API CLI for coding agents" -ForegroundColor DarkGray -NoNewline
    Write-Host '   |' -ForegroundColor Cyan
    Write-Host "  | binaries: $BinaryName  +  $AliasName" -ForegroundColor DarkGray -NoNewline
    Write-Host (' ' * 18) -NoNewline; Write-Host '|' -ForegroundColor Cyan
    Write-Host "  +$line+" -ForegroundColor Cyan
    Write-Host ''
}

# ── Proxy-aware web requests ────────────────────────────────────────────────
function Get-ProxyArgs {
    $proxy = $env:HTTPS_PROXY
    if (-not $proxy) { $proxy = $env:https_proxy }
    if (-not $proxy) { $proxy = $env:HTTP_PROXY }
    if (-not $proxy) { $proxy = $env:http_proxy }
    if ($proxy) { return @{ Proxy = $proxy; ProxyUseDefaultCredentials = $true } }
    return @{}
}

function Invoke-Download {
    param([string]$Url, [string]$OutFile, [string]$Label = 'Downloading')
    Write-Info "$Label $(Split-Path -Leaf $Url)"
    $proxyArgs = Get-ProxyArgs
    Invoke-WebRequest -Uri $Url -OutFile $OutFile -UseBasicParsing -TimeoutSec 1800 @proxyArgs
}

# ── Platform detection ──────────────────────────────────────────────────────
function Get-Target {
    $archEnv = $env:PROCESSOR_ARCHITECTURE
    if ($env:PROCESSOR_ARCHITEW6432) { $archEnv = $env:PROCESSOR_ARCHITEW6432 }
    switch -Wildcard ($archEnv) {
        'ARM64' { return 'aarch64-pc-windows-msvc' }
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        'x86'   { return 'x86_64-pc-windows-msvc' }
        default { return 'x86_64-pc-windows-msvc' }
    }
}

# ── Version resolution (GitHub API -> raw Cargo.toml -> 0.0.0) ───────────────
function Resolve-Version {
    if ($Version) {
        $script:VersionBare = $Version -replace '^v', ''
        $script:Version = "v$($script:VersionBare)"
        $Version = $script:Version
        return
    }
    Write-Info 'Resolving latest version...'
    $proxyArgs = Get-ProxyArgs
    $tag = $null
    try {
        $api = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $rel = Invoke-RestMethod -Uri $api -Headers @{ 'Accept' = 'application/vnd.github+json'; 'User-Agent' = 'franken-snowflake-installer' } -TimeoutSec 45 @proxyArgs
        if ($rel -and $rel.tag_name) { $tag = $rel.tag_name }
    } catch { $tag = $null }

    if ($tag -and $tag -match '^v?[0-9]') {
        $script:Version = $tag
        $Version = $tag
        $script:VersionBare = $tag -replace '^v', ''
        Write-Info "Resolved latest release: $tag"
        return
    }

    # No release tag: only explicit developer source builds may continue.
    $cv = $null
    try {
        $cb = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $raw = "https://raw.githubusercontent.com/$Owner/$Repo/main/Cargo.toml?$cb"
        $body = Invoke-WebRequest -Uri $raw -UseBasicParsing -TimeoutSec 45 @proxyArgs
        $m = [regex]::Match($body.Content, '(?m)^version = "([0-9][^"]*)"')
        if ($m.Success) { $cv = $m.Groups[1].Value }
    } catch { $cv = $null }
    if ($FromSource -or $ArtifactUrl -or $Offline) {
        if (-not $cv) { $cv = '0.0.0' }
        $script:Version = $cv
        $Version = $cv
        $script:VersionBare = $cv -replace '^v', ''
        $script:NoRelease = $true
        Write-Warn 'No tagged release found upstream; continuing with explicit source/artifact input.'
        return
    }

    Write-Err "No tagged GitHub release found for $Owner/$Repo."
    Write-Err 'This installer requires prepared release binaries and will not build from source automatically.'
    Write-Err 'Use -Version vX.Y.Z for a specific release, -ArtifactUrl, -Offline, or explicit -FromSource for developer builds.'
    throw 'release not found'
}

# ── Local checkout detection (build in place when possible) ─────────────────
function Find-LocalCheckout {
    $d = (Get-Location).Path
    while ($d -and (Test-Path $d)) {
        if ((Test-Path (Join-Path $d "crates\$CliPackage\Cargo.toml")) -and (Test-Path (Join-Path $d 'Cargo.toml'))) {
            return $d
        }
        $parent = Split-Path -Parent $d
        if (-not $parent -or $parent -eq $d) { break }
        $d = $parent
    }
    return $null
}

# ── Preflight ───────────────────────────────────────────────────────────────
function Invoke-Preflight {
    Write-Info 'Running preflight checks'
    if (-not (Test-Path $Dest)) {
        try { New-Item -ItemType Directory -Path $Dest -Force | Out-Null }
        catch { Write-Err "Cannot create destination: $Dest"; throw }
    }
    $probe = Join-Path $Dest '.fsnow_write_test'
    try {
        Set-Content -Path $probe -Value 'ok' -ErrorAction Stop
        Remove-Item -Path $probe -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Err "Destination not writable: $Dest (try -Dest DIR, or run elevated for -System)"
        throw
    }
    if (Test-Path (Join-Path $Dest "$BinaryName.exe")) {
        Write-Info "Existing install detected at $Dest\$BinaryName.exe"
    }
}

# ── Already-installed short-circuit (released versions only) ────────────────
function Test-AlreadyInstalled {
    if ($script:NoRelease) { return $false }
    $bin = Join-Path $Dest "$BinaryName.exe"
    if (-not (Test-Path $bin)) { return $false }
    try {
        $out = & $bin capabilities --json 2>$null
        if ($out -match "`"version`"\s*:\s*`"$([regex]::Escape($script:VersionBare))`"") { return $true }
    } catch { }
    return $false
}

# ── Rust / cargo ────────────────────────────────────────────────────────────
function Ensure-Cargo {
    if (Get-Command cargo -ErrorAction SilentlyContinue) { return }
    Write-Warn 'cargo (the Rust toolchain) was not found - it is required to build from source.'
    Write-Info 'franken-snowflake pins a nightly toolchain via rust-toolchain.toml; rustup'
    Write-Info 'will fetch it automatically once installed.'

    $doInstall = $false
    if ($EasyMode) {
        $doInstall = $true
    } else {
        $ans = Read-Host 'Install Rust now via rustup? (y/N)'
        if ($ans -match '^(y|Y)') { $doInstall = $true }
    }

    if ($doInstall) {
        Write-Info 'Downloading rustup-init.exe...'
        $arch = (Get-Target)
        $rustupUrl = if ($arch -like 'aarch64*') {
            'https://static.rust-lang.org/rustup/dist/aarch64-pc-windows-msvc/rustup-init.exe'
        } else {
            'https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe'
        }
        $rustupInit = Join-Path $script:Tmp 'rustup-init.exe'
        Invoke-Download -Url $rustupUrl -OutFile $rustupInit -Label 'Downloading rustup'
        & $rustupInit -y --profile minimal
        $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
        if (Test-Path $cargoBin) { $env:Path = "$cargoBin;$env:Path" }
    }

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Err 'cargo is still unavailable. Install Rust and re-run:'
        Write-Err '    https://rustup.rs   (download and run rustup-init.exe)'
        throw 'cargo not found'
    }
}

# ── Install one binary file (with elevation note for -System) ───────────────
function Install-BinFile {
    param([string]$Src, [string]$Name)
    $target = Join-Path $Dest $Name
    Copy-Item -Path $Src -Destination $target -Force
}

# ── Install the fsnow alias (real exe if present, else copy of canonical) ───
function Install-Alias {
    param([string]$StageDir)
    $aliasSrc = Join-Path $StageDir "$AliasName.exe"
    if (-not (Test-Path $aliasSrc)) {
        $found = Get-ChildItem -Path $StageDir -Recurse -Filter "$AliasName.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $aliasSrc = $found.FullName } else { $aliasSrc = $null }
    }
    if ($aliasSrc -and (Test-Path $aliasSrc)) {
        Install-BinFile -Src $aliasSrc -Name "$AliasName.exe"
        Write-Ok "Installed alias $Dest\$AliasName.exe"
    } else {
        # No standalone fsnow.exe shipped: copy the canonical binary (Windows
        # symlinks need admin/developer mode, so a copy is the reliable alias).
        $canonical = Join-Path $Dest "$BinaryName.exe"
        Copy-Item -Path $canonical -Destination (Join-Path $Dest "$AliasName.exe") -Force
        Write-Ok "Installed alias $Dest\$AliasName.exe (copy of $BinaryName.exe)"
    }
}

# ── Checksum verification ───────────────────────────────────────────────────
function Test-Checksum {
    param([string]$File, [string]$TarName)
    if ($NoVerify) { Write-Warn 'Skipping checksum verification (-NoVerify)'; return }

    $sum = $Checksum
    $proxyArgs = Get-ProxyArgs
    if (-not $sum) {
        $url = $ChecksumUrl
        if (-not $url) { $url = "https://github.com/$Owner/$Repo/releases/download/$Version/SHA256SUMS" }
        try {
            $body = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 45 @proxyArgs).Content
            foreach ($l in ($body -split "`n")) {
                if ($l -match "([0-9a-fA-F]{64})\s+\*?$([regex]::Escape($TarName))\s*$") { $sum = $Matches[1]; break }
            }
        } catch { }
    }
    if (-not $sum) { Write-Warn "No checksum available for $TarName; skipping verification"; return }

    $actual = (Get-FileHash -Path $File -Algorithm SHA256).Hash
    if ($actual.ToLower() -ne $sum.ToLower()) {
        Write-Err "Checksum mismatch for $TarName"
        Write-Err "  expected: $sum"
        Write-Err "  actual:   $actual"
        throw 'checksum mismatch'
    }
    Write-Ok 'Checksum verified'
}

# ── Extract an archive into $Tmp ────────────────────────────────────────────
function Expand-Artifact {
    param([string]$Archive)
    Write-Info "Extracting $(Split-Path -Leaf $Archive)"
    if ($Archive -match '\.zip$') {
        Expand-Archive -Path $Archive -DestinationPath $script:Tmp -Force
    } elseif ($Archive -match '\.(tar\.gz|tgz|tar\.xz|tar)$') {
        # Windows 10+ ships bsdtar as tar.exe.
        if (-not (Get-Command tar -ErrorAction SilentlyContinue)) {
            Write-Err 'tar is required to extract this archive but was not found'
            throw 'tar missing'
        }
        & tar -xf $Archive -C $script:Tmp
        if ($LASTEXITCODE -ne 0) { throw 'tar extraction failed' }
    } else {
        Write-Err "Unknown archive format: $Archive"; throw 'unknown archive'
    }
}

# ── Install from a prebuilt artifact (download or offline) ──────────────────
function Install-FromArtifact {
    param([string]$Archive, [string]$TarName)
    Test-Checksum -File $Archive -TarName $TarName
    Expand-Artifact -Archive $Archive

    $bin = Join-Path $script:Tmp "$BinaryName.exe"
    if (-not (Test-Path $bin)) {
        $found = Get-ChildItem -Path $script:Tmp -Recurse -Filter "$BinaryName.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $bin = $found.FullName } else { $bin = $null }
    }
    if (-not $bin -or -not (Test-Path $bin)) { Write-Err "Binary $BinaryName.exe not found in archive"; throw 'binary missing' }

    Install-BinFile -Src $bin -Name "$BinaryName.exe"
    Write-Ok "Installed $Dest\$BinaryName.exe"
    Install-Alias -StageDir (Split-Path -Parent $bin)
}

function Get-Artifact {
    $script:VersionBare = $Version -replace '^v', ''
    $target = Get-Target
    $ext = 'zip'

    if ($ArtifactUrl) {
        $tar = Split-Path -Leaf $ArtifactUrl
        $url = $ArtifactUrl
    } else {
        $tar = "$BinaryName-v$($script:VersionBare)-$target.$ext"
        $url = "https://github.com/$Owner/$Repo/releases/download/$Version/$tar"
    }

    $out = Join-Path $script:Tmp $tar
    try {
        Invoke-Download -Url $url -OutFile $out -Label "Downloading $BinaryName $Version"
    } catch {
        Write-Err "Release artifact not found or download failed: $tar"
        Write-Err "Expected URL: $url"
        Write-Err 'This installer will not build from source automatically.'
        throw 'release artifact missing'
    }
    Install-FromArtifact -Archive $out -TarName $tar
    return $true
}

function Build-FromSource {
    Ensure-Cargo

    $local = Find-LocalCheckout
    if ($local) {
        $src = $local
        Write-Info "Building from local checkout: $src"
    } else {
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Err 'git is required to fetch the source'; throw 'git missing' }
        $src = Join-Path $script:Tmp 'src'
        Write-Info "Cloning $Owner/$Repo"
        if (-not $script:NoRelease -and $Version) {
            git clone --depth 1 --branch $Version "https://github.com/$Owner/$Repo.git" $src 2>$null
            if ($LASTEXITCODE -ne 0) { git clone --depth 1 "https://github.com/$Owner/$Repo.git" $src }
        } else {
            git clone --depth 1 "https://github.com/$Owner/$Repo.git" $src
        }
        if ($LASTEXITCODE -ne 0) { throw 'git clone failed' }
    }

    # Default build omits the live transport; -Live opts into the real Snowflake
    # SQL API transport via the 'live' cargo feature.
    $cargoArgs = @('build', '--release', '-p', $CliPackage)
    $featureLabel = 'default features (no live transport)'
    if ($Live) {
        $cargoArgs += @('--features', 'live')
        $featureLabel = '--features live (real Snowflake transport)'
    }

    Write-Info "Compiling $CliPackage (cargo build --release, $featureLabel)"
    Write-Info 'This downloads crates and can take several minutes on first build...'
    Push-Location $src
    $code = 1
    try {
        # Unset target redirection so the binaries land where we expect.
        Remove-Item Env:\CARGO_TARGET_DIR       -ErrorAction SilentlyContinue
        Remove-Item Env:\CARGO_BUILD_TARGET     -ErrorAction SilentlyContinue
        Remove-Item Env:\CARGO_BUILD_TARGET_DIR -ErrorAction SilentlyContinue
        & cargo @cargoArgs
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($code -ne 0) {
        Write-Err 'cargo build failed.'
        if ($script:NoRelease -and -not $local) {
            Write-Err 'This pre-release tree pins sibling FrankenSuite crates by path (Asupersync,'
            Write-Err 'etc.). A fresh external clone needs those crates present until the repo'
            Write-Err 'migrates to crates.io dependencies.'
        }
        throw 'build failed'
    }

    $rel = Join-Path $src 'target\release'
    $bin = Join-Path $rel "$BinaryName.exe"
    if (-not (Test-Path $bin)) {
        $found = Get-ChildItem -Path (Join-Path $src 'target') -Recurse -Filter "$BinaryName.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $bin = $found.FullName } else { $bin = $null }
    }
    if (-not $bin -or -not (Test-Path $bin)) { Write-Err "Build succeeded but $BinaryName.exe not found under $rel"; throw 'binary missing' }

    Install-BinFile -Src $bin -Name "$BinaryName.exe"
    Write-Ok "Installed $Dest\$BinaryName.exe (source build)"
    Install-Alias -StageDir (Split-Path -Parent $bin)
}

# ── PATH update (User scope) ────────────────────────────────────────────────
function Update-Path {
    $cur = $env:Path
    if (($cur -split ';') -contains $Dest) { return }
    if ($EasyMode) {
        $scope = if ($System) { 'Machine' } else { 'User' }
        try {
            $existing = [Environment]::GetEnvironmentVariable('Path', $scope)
            if (-not $existing) { $existing = '' }
            if (($existing -split ';') -notcontains $Dest) {
                $newPath = if ($existing) { "$existing;$Dest" } else { $Dest }
                [Environment]::SetEnvironmentVariable('Path', $newPath, $scope)
            }
            $env:Path = "$env:Path;$Dest"
            Write-Warn "Added $Dest to the $scope PATH; open a new terminal to use $BinaryName"
        } catch {
            Write-Warn "Could not update $scope PATH automatically; add $Dest manually"
        }
    } else {
        Write-Warn "Add $Dest to your PATH to use $BinaryName (or re-run with -EasyMode)"
    }
}

# ── Optional completions (probe; this CLI has none today) ───────────────────
function Install-Completions {
    $bin = Join-Path $Dest "$BinaryName.exe"
    if (-not (Test-Path $bin)) { return }
    # Only wire completions if the CLI actually exposes a `completions` subcommand.
    try {
        & $bin completions --help 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            $dir = Join-Path $env:USERPROFILE 'Documents\PowerShell\Completions'
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            & $bin completions powershell > (Join-Path $dir "$BinaryName.ps1")
            Write-Ok "Installed PowerShell completions -> $dir\$BinaryName.ps1"
        }
    } catch { }
    # No `completions` subcommand exists in this CLI yet - skip silently.
}

# ── Self-test (-Verify): real no-account commands only ──────────────────────
function Invoke-SelfTest {
    $bin = Join-Path $Dest "$BinaryName.exe"
    Write-Info 'Running self-test'
    # This CLI has no --version flag; use the dedicated `selftest` command and the
    # no-account `capabilities` smoke (which emits the version in its envelope).
    & $bin selftest 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Err 'selftest failed'; return $false }
    Write-Ok 'selftest passed'
    & $bin capabilities --json 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok 'capabilities smoke passed' } else { Write-Warn 'capabilities smoke did not succeed' }
    return $true
}

# ── Final summary ───────────────────────────────────────────────────────────
function Write-Summary {
    param([string]$Mode)
    if ($Quiet) { return }
    Write-Host ''
    Write-Host '  Installation complete' -ForegroundColor Green
    Write-Host ''
    Write-Host "  Binary:  $Dest\$BinaryName.exe"
    Write-Host "  Alias:   $Dest\$AliasName.exe"
    Write-Host "  Version: $Version ($Mode)"
    Write-Host ''
    Write-Host '  Quick start:' -ForegroundColor Cyan
    Write-Host '    franken-snowflake capabilities --json    # self-describing capability list'
    Write-Host '    franken-snowflake agent-handbook         # embedded handbook'
    Write-Host '    fsnow doctor --json                      # environment diagnostics'
    Write-Host '    franken-snowflake mcp serve --stdio      # serve over MCP'
    Write-Host ''
    Write-Host '  Release binaries include the published live/MCP feature set; credentials are still runtime-gated.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host "  Uninstall: Remove-Item '$Dest\$BinaryName.exe','$Dest\$AliasName.exe'"
    Write-Host ''
}

# ── Main ────────────────────────────────────────────────────────────────────
function Invoke-Main {
    Write-Header
    Resolve-Version

    $script:FromSourceEffective = [bool]$FromSource

    $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("fsnow-install-" + [System.Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null

    try {
        Invoke-Preflight

        if (-not $Force -and (Test-AlreadyInstalled)) {
            Write-Ok "$BinaryName $Version is already installed"
            Write-Info 'Use -Force to reinstall'
            Write-Summary -Mode 'binary'
            return
        }

        $mode = 'binary'
        if ($Offline) {
            if (-not (Test-Path $Offline)) { Write-Err "Offline archive not found: $Offline"; throw 'offline missing' }
            Write-Info "Installing from offline archive: $Offline"
            Install-FromArtifact -Archive $Offline -TarName (Split-Path -Leaf $Offline)
        } elseif ($script:FromSourceEffective) {
            $mode = 'source build'
            Build-FromSource
        } else {
            Get-Artifact | Out-Null
        }

        Update-Path
        Install-Completions

        if ($Verify) {
            if (-not (Invoke-SelfTest)) { Write-Err 'Self-test failed'; throw 'verify failed' }
        }

        Write-Summary -Mode $mode
        Write-Ok 'Done.'
    } finally {
        if ($script:Tmp -and (Test-Path $script:Tmp)) {
            Remove-Item -Path $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Invoke-Main
