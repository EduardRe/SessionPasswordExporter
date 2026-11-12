[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\dist")
)

$ErrorActionPreference = "Stop"
$executableName = "session-password-exporter.exe"
$innoSetupVersion = "7.1.1"
$innoSetupInstallerUrl = "https://github.com/jrsoftware/issrc/releases/download/is-7_1_1/innosetup-7.1.1-x64.exe"
$innoSetupPublisher = "Pyrsys B.V."
$architectures = @(
    [pscustomobject]@{ Name = "x86"; RustTarget = "i686-pc-windows-msvc" },
    [pscustomobject]@{ Name = "x64"; RustTarget = "x86_64-pc-windows-msvc" }
)
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $repositoryRoot

if (-not (Get-Command "rustup" -ErrorAction SilentlyContinue)) {
    throw "rustup was not found. Install Rust from https://rustup.rs, then run this script again."
}

$compilerCandidates = @()
$compilerCommands = Get-Command "ISCC.exe" -All -ErrorAction SilentlyContinue
$compilerCandidates += @($compilerCommands | Where-Object { $_.Source -match "[\\/]Inno Setup 7[\\/]ISCC\.exe$" } | ForEach-Object { $_.Source })
$compilerCandidates += @(
    (Join-Path $env:ProgramFiles "Inno Setup 7\ISCC.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 7\ISCC.exe"),
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe")
)
$installerCompiler = $compilerCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $installerCompiler) {
    Write-Host "Inno Setup 7 is missing. Downloading the signed $innoSetupVersion installer..."
    $bootstrapDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "session-password-exporter-prerequisites-$([guid]::NewGuid().ToString('N'))"
    $bootstrapPath = [System.IO.Path]::GetFullPath($bootstrapDirectory)
    $temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    New-Item -ItemType Directory -Path $bootstrapPath -Force | Out-Null
    try {
        $setupPath = Join-Path $bootstrapPath "innosetup-$innoSetupVersion-x64.exe"
        Invoke-WebRequest -Uri $innoSetupInstallerUrl -OutFile $setupPath -UseBasicParsing

        $signature = Get-AuthenticodeSignature -FilePath $setupPath
        if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*$innoSetupPublisher*") {
            throw "The downloaded Inno Setup installer signature is invalid or has an unexpected publisher."
        }

        $compilerDirectory = Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7"
        Write-Host "Installing Inno Setup 7 for the current user..."
        $installerArguments = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /CURRENTUSER /DIR="{0}"' -f $compilerDirectory
        $installerProcess = Start-Process `
            -FilePath $setupPath `
            -ArgumentList $installerArguments `
            -Wait `
            -PassThru
        if ($installerProcess.ExitCode -ne 0) {
            throw "Inno Setup installation failed with exit code $($installerProcess.ExitCode)."
        }

        $installerCompiler = Join-Path $compilerDirectory "ISCC.exe"
        for ($attempt = 0; $attempt -lt 30 -and -not (Test-Path -LiteralPath $installerCompiler); $attempt++) {
            Start-Sleep -Seconds 1
        }
        if (-not (Test-Path -LiteralPath $installerCompiler)) {
            throw "Inno Setup installation finished, but ISCC.exe was not found at $installerCompiler."
        }
    }
    finally {
        if ($bootstrapPath.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $bootstrapPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

$installedRustTargets = @(& rustup target list --installed)
if ($LASTEXITCODE -ne 0) { throw "Could not list installed Rust targets." }
foreach ($architecture in $architectures) {
    if ($installedRustTargets -notcontains $architecture.RustTarget) {
        $targetInstalled = $false
        for ($attempt = 1; $attempt -le 3 -and -not $targetInstalled; $attempt++) {
            Write-Host "Installing Rust target $($architecture.RustTarget) (attempt $attempt of 3)..."
            & rustup target add $architecture.RustTarget
            $targetInstalled = $LASTEXITCODE -eq 0
            if (-not $targetInstalled -and $attempt -lt 3) {
                Write-Warning "Rust target installation failed; retrying in 3 seconds."
                Start-Sleep -Seconds 3
            }
        }
        if (-not $targetInstalled) {
            throw "Could not install Rust target $($architecture.RustTarget)."
        }
    }
}

$metadataJson = & cargo metadata --no-deps --format-version 1
if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed with exit code $LASTEXITCODE." }
$packageVersion = ($metadataJson | ConvertFrom-Json).packages[0].version

$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputPath -Force | Out-Null

$builtExecutables = @{}
$executablePaths = @{}
$installerPaths = @{}
foreach ($architecture in $architectures) {
    & cargo build --release --target $architecture.RustTarget
    if ($LASTEXITCODE -ne 0) {
        throw "Release build for $($architecture.Name) failed with exit code $LASTEXITCODE."
    }

    $builtPath = Join-Path $repositoryRoot "target\$($architecture.RustTarget)\release\$executableName"
    if (-not (Test-Path -LiteralPath $builtPath)) {
        throw "Release executable for $($architecture.Name) was not created: $builtPath"
    }
    $builtExecutables[$architecture.Name] = $builtPath

    $executablePath = Join-Path $outputPath "session-password-exporter-$($architecture.Name).exe"
    Copy-Item -LiteralPath $builtPath -Destination $executablePath -Force
    $executablePaths[$architecture.Name] = $executablePath

    $installerPaths[$architecture.Name] = Join-Path $outputPath "session-password-exporter-$packageVersion-setup-windows-$($architecture.Name).exe"
}

$portableArchivePath = Join-Path $outputPath "session-password-exporter-v$packageVersion-portable-windows.zip"
$checksumPath = Join-Path $outputPath "session-password-exporter-v$packageVersion-windows.sha256"
$portableStage = Join-Path ([System.IO.Path]::GetTempPath()) "session-password-exporter-portable-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $portableStage -Force | Out-Null
try {
    Copy-Item -LiteralPath "README.md", "README.en.md", "LICENSE", "THIRD_PARTY_NOTICES.md" -Destination $portableStage
    Set-Content -LiteralPath (Join-Path $portableStage "portable.mode") -Value "Portable mode" -Encoding ascii
    foreach ($architecture in $architectures) {
        $architectureDirectory = Join-Path $portableStage $architecture.Name
        New-Item -ItemType Directory -Path $architectureDirectory -Force | Out-Null
        Copy-Item -LiteralPath $builtExecutables[$architecture.Name] `
            -Destination (Join-Path $architectureDirectory $executableName)
    }
    Remove-Item -LiteralPath $portableArchivePath -Force -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $portableStage "*") -DestinationPath $portableArchivePath -CompressionLevel Optimal
}
finally {
    $temporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $portableStagePath = [System.IO.Path]::GetFullPath($portableStage)
    if ($portableStagePath.StartsWith($temporaryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $portableStagePath -Recurse -Force -ErrorAction SilentlyContinue
    }
}

foreach ($architecture in $architectures) {
    Remove-Item -LiteralPath $installerPaths[$architecture.Name] -Force -ErrorAction SilentlyContinue
    $installerScript = Join-Path $repositoryRoot "installer\SessionPasswordExporter-$($architecture.Name).iss"
    & $installerCompiler `
        "/DAppVersion=$packageVersion" `
        "/DSourceRoot=$repositoryRoot" `
        "/DOutputDirectory=$outputPath" `
        $installerScript
    if ($LASTEXITCODE -ne 0) {
        throw "Installer compilation for $($architecture.Name) failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $installerPaths[$architecture.Name])) {
        throw "Installer output for $($architecture.Name) was not created: $($installerPaths[$architecture.Name])"
    }
}

$packagePaths = @($executablePaths.Values) + @($installerPaths.Values) + @($portableArchivePath)
Copy-Item -LiteralPath "THIRD_PARTY_NOTICES.md" -Destination $outputPath
$checksumLines = foreach ($path in $packagePaths) {
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $(Split-Path -Leaf $path)"
}
Set-Content -LiteralPath $checksumPath -Value $checksumLines -Encoding ascii

Write-Host "Windows packages created in: $outputPath"
foreach ($path in $packagePaths) {
    Write-Host "  $(Split-Path -Leaf $path)"
}
Write-Host "  $(Split-Path -Leaf $checksumPath)"
