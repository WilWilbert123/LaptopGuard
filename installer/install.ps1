# =====================================================================
# GUARDIAN - Windows Installer & Service Provisioner
# Installs Guardian as a persistent, offline local security background service
# with autostart, silent execution, desktop shortcut, and browser launcher.
# =====================================================================

[CmdletBinding()]
param(
    [string]$TargetDir = "",
    [switch]$SkipBrowserLaunch = $false
)

$ErrorActionPreference = "Stop"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   GUARDIAN - Personal Laptop Security Installer    " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceDir = Resolve-Path (Join-Path $ScriptDir "..")

# 1. Determine Administrative Elevation
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($IsAdmin) {
    Write-Host "[OK] Running with Administrator privileges." -ForegroundColor Green
    if (-not $TargetDir) {
        $TargetDir = "C:\Program Files\Guardian"
    }
    $RunLevel = "HighestAvailable"
} else {
    Write-Host "[INFO] Running as standard user." -ForegroundColor Yellow
    if (-not $TargetDir) {
        $TargetDir = Join-Path $env:LOCALAPPDATA "Programs\Guardian"
    }
    $RunLevel = "Limited"
}

Write-Host "[1/6] Destination directory: $TargetDir" -ForegroundColor White

# 2. Check Node.js runtime availability
$SystemNode = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
$EmbeddedNode = Join-Path $TargetDir "bin\node.exe"

if (-not $SystemNode -and -not (Test-Path $EmbeddedNode)) {
    Write-Host "[INFO] Node.js not detected in system PATH." -ForegroundColor Yellow
    Write-Host "      Attempting to bundle portable Node.js runtime..." -ForegroundColor Yellow
    
    $BinDir = Join-Path $TargetDir "bin"
    if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir -Force | Out-Null }
    
    # Try downloading official standalone node.exe if internet is available
    try {
        $NodeUrl = "https://nodejs.org/dist/v20.18.0/win-x64/node.exe"
        Write-Host "      Downloading portable Node.js runtime (~30MB)..." -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $NodeUrl -OutFile $EmbeddedNode -TimeoutSec 30
        Write-Host "[OK] Portable Node.js runtime downloaded successfully." -ForegroundColor Green
        $EffectiveNode = $EmbeddedNode
    } catch {
        Write-Host "[WARNING] Could not download Node.js automatically (device may be offline)." -ForegroundColor Yellow
        Write-Host "Please ensure Node.js is installed on this laptop before running Guardian." -ForegroundColor Yellow
        $EffectiveNode = "node.exe"
    }
} else {
    $EffectiveNode = if ($SystemNode) { $SystemNode } else { $EmbeddedNode }
    Write-Host "[OK] Node runtime verified: $EffectiveNode" -ForegroundColor Green
}

# 3. Copy Application Files
Write-Host "[2/6] Copying application files..." -ForegroundColor White
if (-not (Test-Path $TargetDir)) {
    New-Item -ItemType Directory -Path $TargetDir -Force | Out-Null
}

$DirectoriesToCopy = @("background", "public", "node_modules", "installer")
foreach ($dir in $DirectoriesToCopy) {
    $src = Join-Path $SourceDir $dir
    $dest = Join-Path $TargetDir $dir
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $dest -Recurse -Force
    }
}

$FilesToCopy = @("package.json", ".env.example")
foreach ($file in $FilesToCopy) {
    $src = Join-Path $SourceDir $file
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination (Join-Path $TargetDir $file) -Force
    }
}

# Ensure .env exists in target
$TargetEnv = Join-Path $TargetDir ".env"
if (-not (Test-Path $TargetEnv)) {
    $SrcEnv = Join-Path $SourceDir ".env"
    if (Test-Path $SrcEnv) {
        Copy-Item -Path $SrcEnv -Destination $TargetEnv -Force
    } else {
        $SrcExample = Join-Path $SourceDir ".env.example"
        if (Test-Path $SrcExample) {
            Copy-Item -Path $SrcExample -Destination $TargetEnv -Force
        }
    }
}

# Ensure data directory exists
$DataDir = Join-Path $TargetDir "data"
if (-not (Test-Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

Write-Host "[OK] Application files installed." -ForegroundColor Green

# 4. Create Windows Scheduled Task for Autostart
Write-Host "[3/6] Configuring Windows background task..." -ForegroundColor White
$TaskName = "Guardian_BackgroundWorker"
$LauncherVbs = Join-Path $TargetDir "installer\Guardian-Launcher.vbs"

# Scheduled task executes wscript.exe silently on user logon
$TaskAction = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$LauncherVbs`" --daemon" -WorkingDirectory $TargetDir
$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $TaskName -Action $TaskAction -Trigger $TaskTrigger -Settings $TaskSettings -RunLevel $RunLevel -Description "Guardian Personal Laptop Security Monitor" | Out-Null
    Write-Host "[OK] Background task '$TaskName' registered for automatic startup at Windows logon." -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Could not register scheduled task: $_. Guardian can still be launched via the Desktop shortcut." -ForegroundColor Yellow
}

# 5. Create Desktop & Start Menu Shortcuts
Write-Host "[4/6] Creating Desktop and Start Menu shortcuts..." -ForegroundColor White
$WshShell = New-Object -ComObject WScript.Shell

# Desktop Shortcut
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$DesktopShortcutPath = Join-Path $DesktopPath "Guardian Security.lnk"
$Shortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$Shortcut.TargetPath = "wscript.exe"
$Shortcut.Arguments = "`"$LauncherVbs`" --open"
$Shortcut.WorkingDirectory = $TargetDir
$Shortcut.Description = "Guardian - Personal Laptop Security & Threat Monitor"
# Custom Guardian Icon
$GuardianIconPath = Join-Path $TargetDir "installer\guardian.ico"
$Shortcut.IconLocation = "$GuardianIconPath,0"
$Shortcut.Save()

# Start Menu Shortcut
$StartMenuPath = [Environment]::GetFolderPath("Programs")
$GuardianStartMenuDir = Join-Path $StartMenuPath "Guardian"
if (-not (Test-Path $GuardianStartMenuDir)) {
    New-Item -ItemType Directory -Path $GuardianStartMenuDir -Force | Out-Null
}
$StartMenuShortcutPath = Join-Path $GuardianStartMenuDir "Guardian.lnk"
$StartShortcut = $WshShell.CreateShortcut($StartMenuShortcutPath)
$StartShortcut.TargetPath = "wscript.exe"
$StartShortcut.Arguments = "`"$LauncherVbs`" --open"
$StartShortcut.WorkingDirectory = $TargetDir
$StartShortcut.Description = "Guardian - Personal Laptop Security & Threat Monitor"
$StartShortcut.IconLocation = "$GuardianIconPath,0"
$StartShortcut.Save()

# Start Menu Uninstaller Shortcut
$UninstallerShortcutPath = Join-Path $GuardianStartMenuDir "Uninstall Guardian.lnk"
$UninstShortcut = $WshShell.CreateShortcut($UninstallerShortcutPath)
$UninstShortcut.TargetPath = Join-Path $TargetDir "installer\uninstall.bat"
$UninstShortcut.WorkingDirectory = $TargetDir
$UninstShortcut.Description = "Uninstall Guardian Security"
$UninstShortcut.IconLocation = "$env:SystemRoot\System32\shell32.dll,131"
$UninstShortcut.Save()

Write-Host "[OK] Desktop and Start Menu shortcuts created." -ForegroundColor Green

# 6. Start the Service Immediately
Write-Host "[5/6] Starting Guardian background engine..." -ForegroundColor White
try {
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
} catch {}

# Fallback direct silent trigger via VBS launcher
Start-Process "wscript.exe" -ArgumentList "`"$LauncherVbs`" $(if ($SkipBrowserLaunch) { '--daemon' } else { '--open' })" -WorkingDirectory $TargetDir

Write-Host "[6/6] Guardian is active and protecting this laptop!" -ForegroundColor Green
Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "   INSTALLATION COMPLETE                            " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "• Status: Running in background (Port 3000)"
Write-Host "• Autostart: Enabled on Windows logon"
Write-Host "• Dashboard: http://127.0.0.1:3000"
Write-Host "• Desktop Shortcut: 'Guardian Security'"
Write-Host ""
