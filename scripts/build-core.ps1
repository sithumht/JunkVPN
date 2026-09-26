<#
.SYNOPSIS
    Builds the Go core (warpcore) into an Android AAR with gomobile.

.DESCRIPTION
    Produces android/app/libs/warpcore.aar, which the app module consumes.

    Prerequisites:
      * Go 1.21+ on PATH
      * gomobile on PATH:  go install golang.org/x/mobile/cmd/gomobile@latest
      * The module tool directive:  go get -tool golang.org/x/mobile/cmd/gobind
        (already recorded in go.mod for this repository)
      * Android SDK (ANDROID_HOME) and at least one NDK under sdk/ndk/

.EXAMPLE
    ./scripts/build-core.ps1
    ./scripts/build-core.ps1 -AndroidApi 26 -Output android/app/libs/warpcore.aar
#>
param(
    # Minimum Android API level the AAR supports (matches minSdk).
    [string]$AndroidApi = "26",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
if (-not $Output) { $Output = Join-Path $root "android\app\libs\warpcore.aar" }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go toolchain not found on PATH."
}
if (-not (Get-Command gomobile -ErrorAction SilentlyContinue)) {
    throw "gomobile not found on PATH. Run: go install golang.org/x/mobile/cmd/gomobile@latest"
}

if (-not $env:ANDROID_HOME) {
    if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_HOME = $env:ANDROID_SDK_ROOT }
    else { throw "Set ANDROID_HOME (or ANDROID_SDK_ROOT) to your Android SDK." }
}
if (-not $env:ANDROID_NDK_HOME) {
    $ndkRoot = Join-Path $env:ANDROID_HOME "ndk"
    if (Test-Path $ndkRoot) {
        $newest = Get-ChildItem $ndkRoot -Directory |
            Sort-Object { [version]($_.Name -replace '[^\d.].*', '') } -Descending |
            Select-Object -First 1
        if ($newest) { $env:ANDROID_NDK_HOME = $newest.FullName }
    }
}

New-Item -ItemType Directory -Force (Split-Path -Parent $Output) | Out-Null

Push-Location $root
try {
    gomobile bind -target=android -androidapi $AndroidApi -o $Output .\warpcore
    if ($LASTEXITCODE -ne 0) { throw "gomobile bind failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
}

"Built {0} ({1:N0} bytes)" -f $Output, (Get-Item $Output).Length
