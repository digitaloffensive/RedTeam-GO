<#
.SYNOPSIS
    Build FileScanner for Windows targets.
    Detects your Go version and warns if it will not run on older Windows.

.DESCRIPTION
    Go 1.21 and later dropped support for Windows 7, 8, 8.1,
    Server 2008 R2, 2012, and 2012 R2.  Binaries built with Go 1.21+
    call ProcessPrng() from bcryptprimitives.dll at startup — a function
    that does not exist on those older systems — and immediately crash
    with "not compatible with this version of Windows".

    Go 1.20 is the last toolchain that produces binaries running on
    Windows 7 SP1 / Server 2008 R2 and later.

.PARAMETER Target
    Which binary to build:
      all       — amd64 + arm64  (default)
      amd64     — 64-bit Intel/AMD
      arm64     — 64-bit ARM (Surface Pro X, newer servers)

.PARAMETER OldWindows
    Pass -OldWindows to enforce Go 1.20.x and error if a newer toolchain
    is active.  Use this when deploying to Windows 7/8/Server 2008-2012.

.EXAMPLE
    .\build_windows.ps1
    .\build_windows.ps1 -Target amd64
    .\build_windows.ps1 -OldWindows -Target amd64
#>

param(
    [ValidateSet("all","amd64","arm64")]
    [string]$Target = "all",
    [switch]$OldWindows
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Go version detection ──────────────────────────────────────────────────────
$goVersionOutput = & go version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Go is not installed or not in PATH. Download from https://go.dev/dl/"
    exit 1
}

# Parse "go version go1.22.2 windows/amd64" → major=1, minor=22
if ($goVersionOutput -match 'go(\d+)\.(\d+)') {
    $goMajor = [int]$Matches[1]
    $goMinor = [int]$Matches[2]
} else {
    Write-Error "Could not parse Go version from: $goVersionOutput"
    exit 1
}

Write-Host "Detected: $goVersionOutput" -ForegroundColor Cyan

# ── Compatibility checks ──────────────────────────────────────────────────────
$isModern = ($goMajor -gt 1) -or ($goMajor -eq 1 -and $goMinor -ge 21)

if ($OldWindows) {
    if ($isModern) {
        Write-Host ""
        Write-Host "ERROR: -OldWindows requires Go 1.20.x but you have Go $goMajor.$goMinor" -ForegroundColor Red
        Write-Host ""
        Write-Host "Go 1.21+ binaries WILL NOT RUN on:" -ForegroundColor Yellow
        Write-Host "  - Windows 7 / Server 2008 R2  (version 6.1)" -ForegroundColor Yellow
        Write-Host "  - Windows 8 / Server 2012     (version 6.2)" -ForegroundColor Yellow
        Write-Host "  - Windows 8.1 / Server 2012 R2 (version 6.3)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "They crash immediately with:" -ForegroundColor Yellow
        Write-Host "  'This version of Windows is not compatible with this application'" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Solution: install Go 1.20.x from https://go.dev/dl/#go1.20.14" -ForegroundColor Green
        Write-Host "  Then re-run: .\build_windows.ps1 -OldWindows" -ForegroundColor Green
        exit 1
    }
    Write-Host "Building with Go $goMajor.$goMinor (Windows 7+ compatible)" -ForegroundColor Green
} else {
    if ($isModern) {
        Write-Host ""
        Write-Host "NOTE: Go $goMajor.$goMinor produces binaries requiring Windows 10 / Server 2016+" -ForegroundColor Yellow
        Write-Host "      If you need to support older Windows, use: .\build_windows.ps1 -OldWindows" -ForegroundColor Yellow
        Write-Host ""
    }
}

# ── Build function ────────────────────────────────────────────────────────────
function Build-Target {
    param([string]$Arch)

    $outName = "scanner_windows_$Arch.exe"
    $suffix  = if ($isModern) { "win10+" } else { "win7+" }
    $outName = "scanner_windows_${Arch}_${suffix}.exe"

    Write-Host "Building $outName ..." -ForegroundColor Cyan
    $env:GOOS   = "windows"
    $env:GOARCH = $Arch

    & go build -trimpath -ldflags="-s -w" -o $outName ./cmd/scanner/
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed for $Arch"
        exit 1
    }

    $size = (Get-Item $outName).Length / 1MB
    Write-Host "  OK  $outName  ($([math]::Round($size,1)) MB)" -ForegroundColor Green
}

# ── Run builds ────────────────────────────────────────────────────────────────
Push-Location $PSScriptRoot

try {
    switch ($Target) {
        "amd64" { Build-Target "amd64" }
        "arm64" { Build-Target "arm64" }
        "all"   { Build-Target "amd64"; Build-Target "arm64" }
    }
} finally {
    $env:GOOS   = $null
    $env:GOARCH = $null
    Pop-Location
}

Write-Host ""
Write-Host "Build complete." -ForegroundColor Green
if ($isModern) {
    Write-Host "Minimum target: Windows 10 (build 10586) / Server 2016+" -ForegroundColor Cyan
} else {
    Write-Host "Minimum target: Windows 7 SP1 / Server 2008 R2+" -ForegroundColor Cyan
}
