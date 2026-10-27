# =====================================================================
# Build C# Standalone Package
# Compiles Guardian C# (.NET 9.0) and stages all engine assets into a 
# self-contained distribution package.
# =====================================================================

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   BUILDING GUARDIAN C# STANDALONE PACKAGE           " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Publish GuardianApp (C# WinForms WebView2 Desktop App)
Write-Host "[1/5] Compiling Guardian C# Desktop App..." -ForegroundColor White
$AppProject = Join-Path $ProjectRoot "GuardianApp\Guardian.csproj"
$PublishDir = Join-Path $ProjectRoot "GuardianApp\publish"

dotnet publish $AppProject -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $PublishDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed!" }
Write-Host "[OK] Guardian.exe compiled successfully." -ForegroundColor Green

# 2. Prepare Staging Directory
Write-Host "[2/5] Preparing staging directory..." -ForegroundColor White
$StagingDir = Join-Path $ProjectRoot "dist\staging"
if (Test-Path $StagingDir) { Remove-Item -Path $StagingDir -Recurse -Force }
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null

# Copy C# binaries
Copy-Item (Join-Path $PublishDir "Guardian.exe") -Destination $StagingDir -Force
$IcoSource = if (Test-Path (Join-Path $PublishDir "guardian.ico")) { Join-Path $PublishDir "guardian.ico" } else { Join-Path $ProjectRoot "GuardianApp\guardian.ico" }
Copy-Item $IcoSource -Destination $StagingDir -Force

# Copy WebView2Loader.dll native library
$WvCandidates = @(
    (Join-Path $PublishDir "WebView2Loader.dll"),
    (Join-Path $PublishDir "runtimes\win-x64\native\WebView2Loader.dll"),
    (Join-Path $ProjectRoot "GuardianApp\bin\Release\net9.0-windows\win-x64\WebView2Loader.dll"),
    (Join-Path $ProjectRoot "GuardianApp\bin\Release\net9.0-windows\win-x64\runtimes\win-x64\native\WebView2Loader.dll")
)

$foundWv = $false
foreach ($wv in $WvCandidates) {
    if (Test-Path $wv) {
        # Copy to root of staging directory (next to Guardian.exe)
        Copy-Item $wv -Destination $StagingDir -Force
        # Also copy runtimes directory
        $RuntimesDst = Join-Path $StagingDir "runtimes\win-x64\native"
        New-Item -ItemType Directory -Path $RuntimesDst -Force | Out-Null
        Copy-Item $wv -Destination $RuntimesDst -Force
        Write-Host "[OK] Bundled WebView2Loader.dll ($wv)" -ForegroundColor Green
        $foundWv = $true
        break
    }
}
if (-not $foundWv) {
    Write-Warning "Could not locate WebView2Loader.dll in build output!"
}

# 3. Assemble engine directory
Write-Host "[3/5] Bundling background engine and portable Node runtime..." -ForegroundColor White
$EngineDir = Join-Path $StagingDir "engine"
New-Item -ItemType Directory -Path $EngineDir -Force | Out-Null

$DirsToCopy = @("background", "public", "node_modules")
foreach ($d in $DirsToCopy) {
    $src = Join-Path $ProjectRoot $d
    $dst = Join-Path $EngineDir $d
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Recurse -Force
    }
}

$FilesToCopy = @("package.json", ".env.example", ".env")
foreach ($f in $FilesToCopy) {
    $src = Join-Path $ProjectRoot $f
    $dst = Join-Path $EngineDir $f
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dst -Force
    }
}

# Ensure data directory exists
New-Item -ItemType Directory -Path (Join-Path $EngineDir "data") -Force | Out-Null

# Copy portable node.exe
$BinDir = Join-Path $EngineDir "bin"
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
$SystemNode = "C:\Program Files\nodejs\node.exe"
if (Test-Path $SystemNode) {
    Copy-Item -Path $SystemNode -Destination (Join-Path $BinDir "node.exe") -Force
    Write-Host "[OK] Portable Node.js runtime bundled into engine/bin/node.exe" -ForegroundColor Green
} else {
    Write-Warning "Could not find $SystemNode to bundle."
}

# 4. Create ZIP package for the Installer
Write-Host "[4/5] Compressing payload into Guardian-Payload.zip..." -ForegroundColor White
$DistDir = Join-Path $ProjectRoot "dist"
$PayloadZip = Join-Path $DistDir "Guardian-Payload.zip"
if (Test-Path $PayloadZip) { Remove-Item $PayloadZip -Force }

Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($StagingDir, $PayloadZip, [System.IO.Compression.CompressionLevel]::Optimal, $false)
Write-Host "[OK] Payload compressed: $((Get-Item $PayloadZip).Length / 1MB) MB" -ForegroundColor Green

Write-Host "[5/5] Staging complete." -ForegroundColor Green
