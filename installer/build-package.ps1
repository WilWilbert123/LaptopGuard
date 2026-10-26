# =====================================================================
# GUARDIAN - Distribution Packager Script
# Prepares a clean release bundle in dist/Guardian-v1.0.0-Windows.zip
# ready to distribute to other Windows laptops.
# =====================================================================

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   BUILDING GUARDIAN RELEASE PACKAGE                " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DistDir = Join-Path $ProjectRoot "dist"
$StagingDir = Join-Path $DistDir "Guardian"
$ZipFile = Join-Path $DistDir "Guardian-v1.0.0-Windows.zip"

# 1. Clean previous build artifacts
Write-Host "[1/4] Preparing output directory..." -ForegroundColor White
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
if (Test-Path $ZipFile) { Remove-Item -Path $ZipFile -Force }
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# 2. Copy production assets
Write-Host "[2/4] Bundling Guardian core files..." -ForegroundColor White
$IncludeFolders = @("background", "public", "node_modules", "installer")
foreach ($folder in $IncludeFolders) {
    $src = Join-Path $ProjectRoot $folder
    $dest = Join-Path $StagingDir $folder
    if (Test-Path $src) {
        Write-Host "      + Copying $folder/" -ForegroundColor Gray
        Copy-Item -Path $src -Destination $dest -Recurse -Force
    }
}

$IncludeFiles = @("package.json", ".env.example", "SETUP_GUIDE.md")
foreach ($file in $IncludeFiles) {
    $src = Join-Path $ProjectRoot $file
    if (Test-Path $src) {
        Write-Host "      + Copying $file" -ForegroundColor Gray
        Copy-Item -Path $src -Destination (Join-Path $StagingDir $file) -Force
    }
}

# Put install.bat and uninstall.bat in the root of the package for easy double-clicking
Copy-Item -Path (Join-Path $ProjectRoot "installer\install.bat") -Destination (Join-Path $StagingDir "Install-Guardian.bat") -Force
Copy-Item -Path (Join-Path $ProjectRoot "installer\uninstall.bat") -Destination (Join-Path $StagingDir "Uninstall-Guardian.bat") -Force

# Create empty data folder
New-Item -ItemType Directory -Path (Join-Path $StagingDir "data") -Force | Out-Null

# 3. Compile Inno Setup installer if iscc.exe is installed
Write-Host "[3/4] Checking for Inno Setup compiler..." -ForegroundColor White
$Iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
if (-not $Iscc -and (Test-Path "C:\Program Files (x86)\Inno Setup 6\ISCC.exe")) {
    $Iscc = "C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
}

if ($Iscc) {
    Write-Host "[OK] Compiling Guardian-Setup.exe with Inno Setup..." -ForegroundColor Green
    & "$Iscc" (Join-Path $ScriptDir "guardian-setup.iss")
} else {
    Write-Host "[INFO] Inno Setup (ISCC.exe) not installed. Skipping .exe compile." -ForegroundColor Gray
    Write-Host "       (You can still install and use the ZIP package directly with Install-Guardian.bat)" -ForegroundColor Gray
}

# 4. Generate portable ZIP archive
Write-Host "[4/4] Creating distribution ZIP archive..." -ForegroundColor White
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipFile -CompressionLevel Optimal
Write-Host "[SUCCESS] Package generated at:" -ForegroundColor Green
Write-Host "          $ZipFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "To deploy on another laptop:" -ForegroundColor Yellow
Write-Host "1. Copy '$ZipFile' to the other laptop."
Write-Host "2. Extract the ZIP."
Write-Host "3. Double-click 'Install-Guardian.bat'."
Write-Host ""
