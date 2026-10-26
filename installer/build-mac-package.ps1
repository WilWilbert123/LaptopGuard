# =====================================================================
# GUARDIAN - macOS Distribution Packager Script
# Prepares clean release bundles in:
#   dist/Guardian-v1.0.0-macOS.zip
#   dist/Guardian-v1.0.0-macOS.tar.gz
# ready to distribute to any MacBook (Apple Silicon / Intel).
# =====================================================================

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   BUILDING GUARDIAN macOS RELEASE PACKAGE          " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DistDir = Join-Path $ProjectRoot "dist"
$StagingDir = Join-Path $DistDir "Guardian-macOS"
$ZipFile = Join-Path $DistDir "Guardian-v1.0.0-macOS.zip"
$TarFile = Join-Path $DistDir "Guardian-v1.0.0-macOS.tar.gz"

# 1. Clean previous build artifacts
Write-Host "[1/4] Preparing output directory..." -ForegroundColor White
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
if (Test-Path $ZipFile) { Remove-Item -Path $ZipFile -Force }
if (Test-Path $TarFile) { Remove-Item -Path $TarFile -Force }
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# 2. Copy production assets
Write-Host "[2/4] Bundling Guardian core files for macOS..." -ForegroundColor White
$IncludeFolders = @("background", "public", "node_modules", "installer")
foreach ($folder in $IncludeFolders) {
    $src = Join-Path $ProjectRoot $folder
    $dest = Join-Path $StagingDir $folder
    if (Test-Path $src) {
        Write-Host "      + Copying $folder/" -ForegroundColor Gray
        Copy-Item -Path $src -Destination $dest -Recurse -Force
    }
}

$IncludeFiles = @("package.json", ".env.example", "SETUP_GUIDE_MAC.md")
foreach ($file in $IncludeFiles) {
    $src = Join-Path $ProjectRoot $file
    if (Test-Path $src) {
        Write-Host "      + Copying $file" -ForegroundColor Gray
        Copy-Item -Path $src -Destination (Join-Path $StagingDir $file) -Force
    }
}

# Put Finder-double-clickable scripts in the root of the staging folder
Copy-Item -Path (Join-Path $ProjectRoot "installer\Install-Guardian.command") -Destination (Join-Path $StagingDir "Install-Guardian.command") -Force
Copy-Item -Path (Join-Path $ProjectRoot "installer\Launch-Guardian-App.command") -Destination (Join-Path $StagingDir "Launch-Guardian-App.command") -Force
Copy-Item -Path (Join-Path $ProjectRoot "installer\Uninstall-Guardian.command") -Destination (Join-Path $StagingDir "Uninstall-Guardian.command") -Force
Copy-Item -Path (Join-Path $ProjectRoot "installer\install-mac.sh") -Destination (Join-Path $StagingDir "install.sh") -Force
Copy-Item -Path (Join-Path $ProjectRoot "installer\uninstall-mac.sh") -Destination (Join-Path $StagingDir "uninstall.sh") -Force

# Create empty data folder
New-Item -ItemType Directory -Path (Join-Path $StagingDir "data") -Force | Out-Null

# 3. Create macOS ZIP archive
Write-Host "[3/4] Creating distribution ZIP archive..." -ForegroundColor White
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipFile -CompressionLevel Optimal
Write-Host "[SUCCESS] macOS ZIP package: $ZipFile" -ForegroundColor Green

# 4. Create macOS tar.gz archive using native tar command if available
Write-Host "[4/4] Creating distribution tar.gz archive..." -ForegroundColor White
try {
    tar -czf "$TarFile" -C "$DistDir" "Guardian-macOS"
    Write-Host "[SUCCESS] macOS tar.gz package: $TarFile" -ForegroundColor Green
} catch {
    Write-Host "[INFO] tar command not available or failed. ZIP package is ready." -ForegroundColor Gray
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   macOS RELEASE PACKAGING COMPLETE                 " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "To install on your MacBook:" -ForegroundColor Yellow
Write-Host "1. Copy '$ZipFile' to your MacBook."
Write-Host "2. Double-click the ZIP to extract it."
Write-Host "3. Double-click 'Install-Guardian.command' in Finder."
Write-Host ""
