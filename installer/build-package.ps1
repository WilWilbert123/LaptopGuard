# =====================================================================
# GUARDIAN - Distribution Packager Script
# Compiles the standalone C# Desktop App & C# Setup Wizard (.exe)
# Generates: dist/Guardian-Setup.exe
# =====================================================================

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   BUILDING GUARDIAN C# STANDALONE INSTALLER         " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$DistDir = Join-Path $ProjectRoot "dist"

# 1. Build staging payload with C# Desktop app & bundled engine
Write-Host "[1/3] Compiling C# Desktop App and assembling payload..." -ForegroundColor White
$BuildScript = Join-Path $ProjectRoot "scripts\build-csharp-package.ps1"
& powershell -ExecutionPolicy Bypass -File "$BuildScript"
if ($LASTEXITCODE -ne 0) { throw "Staging build failed!" }

# 2. Build the C# Setup Wizard (Guardian-Setup.exe)
Write-Host "[2/3] Compiling Guardian-Setup.exe installer..." -ForegroundColor White
$InstallerProj = Join-Path $ProjectRoot "GuardianInstaller\GuardianInstaller.csproj"
$InstallerOut = Join-Path $DistDir "installer"

dotnet publish "$InstallerProj" -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o "$InstallerOut"
if ($LASTEXITCODE -ne 0) { throw "Installer compilation failed!" }

# Copy single .exe to dist root (both Guardian-Setup.exe and Guardian_Installer.exe)
$FinalExe = Join-Path $DistDir "Guardian-Setup.exe"
Copy-Item (Join-Path $InstallerOut "Guardian-Setup.exe") -Destination $FinalExe -Force
$AliasExe = Join-Path $DistDir "Guardian_Installer.exe"
Copy-Item $FinalExe -Destination $AliasExe -Force

Write-Host "[3/3] Final installer compiled successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   STANDALONE C# INSTALLER READY                    " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "• Location: $FinalExe" -ForegroundColor Green
Write-Host "• Size: $([math]::Round((Get-Item $FinalExe).Length / 1MB, 2)) MB" -ForegroundColor White
Write-Host "• Type: Native Windows Standalone Executable (C# .NET 9.0)" -ForegroundColor White
Write-Host ""
Write-Host "How to distribute to other laptops:" -ForegroundColor Yellow
Write-Host "1. Simply copy 'Guardian-Setup.exe' to any USB drive or target laptop."
Write-Host "2. Double-click 'Guardian-Setup.exe' to install."
Write-Host "3. No source code, Node.js, or browser needed!"
Write-Host ""
