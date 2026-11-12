[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ReleaseDirectory
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command "gh" -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) was not found on PATH."
}
if (-not $env:GITHUB_SHA) {
    throw "GITHUB_SHA is not set; run this script from a GitHub Actions job."
}
if (-not $env:GH_TOKEN) {
    throw "GH_TOKEN is not set."
}

$metadataJson = & cargo metadata --no-deps --format-version 1
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed with exit code $LASTEXITCODE."
}
$packageVersion = ($metadataJson | ConvertFrom-Json).packages[0].version
$shortCommit = $env:GITHUB_SHA.Substring(0, 12)
$releaseTag = "master-$shortCommit"
$releaseTitle = "Session Password Exporter $packageVersion (master $shortCommit)"
$releaseNotes = "Automated release from master at commit $env:GITHUB_SHA."
$releasePath = [System.IO.Path]::GetFullPath($ReleaseDirectory)

$assetPaths = @(
    (Join-Path $releasePath "session-password-exporter-x86.exe"),
    (Join-Path $releasePath "session-password-exporter-x64.exe"),
    (Join-Path $releasePath "session-password-exporter-$packageVersion-setup-windows-x86.exe"),
    (Join-Path $releasePath "session-password-exporter-$packageVersion-setup-windows-x64.exe"),
    (Join-Path $releasePath "session-password-exporter-v$packageVersion-portable-windows.zip"),
    (Join-Path $releasePath "THIRD_PARTY_NOTICES.md"),
    (Join-Path $releasePath "session-password-exporter-v$packageVersion-windows.sha256")
)
foreach ($assetPath in $assetPaths) {
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "Release asset was not created: $assetPath"
    }
}

# A retry of the same commit updates its release instead of failing on an existing tag.
$PSNativeCommandUseErrorActionPreference = $false
$null = & gh release view $releaseTag --json tagName 2>$null
$releaseExists = $LASTEXITCODE -eq 0

if ($releaseExists) {
    & gh release upload $releaseTag @assetPaths --clobber
    if ($LASTEXITCODE -ne 0) {
        throw "Could not update assets for release $releaseTag."
    }

    & gh release edit $releaseTag `
        --title $releaseTitle `
        --notes $releaseNotes `
        --latest
} else {
    & gh release create $releaseTag @assetPaths `
        --title $releaseTitle `
        --notes $releaseNotes `
        --latest `
        --target $env:GITHUB_SHA
}
if ($LASTEXITCODE -ne 0) {
    throw "Could not publish release $releaseTag."
}

Write-Host "Published release: $releaseTag"
