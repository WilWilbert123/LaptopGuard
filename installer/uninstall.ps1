# =====================================================================
# GUARDIAN - Comprehensive Uninstaller Script
# Completely stops background monitoring, unregisters autostart,
# deletes shortcuts, and cleans up installation files.
# =====================================================================

$ErrorActionPreference = "SilentlyContinue"

Write-Host "====================================================" -ForegroundColor Yellow
Write-Host "   GUARDIAN - Complete Uninstallation               " -ForegroundColor Yellow
Write-Host "====================================================" -ForegroundColor Yellow
Write-Host ""

# 1. Terminate Guardian Processes
Write-Host "[1/5] Stopping Guardian processes..." -ForegroundColor White

# Stop C# Desktop App
Get-Process -Name "Guardian" -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Write-Host "      + Terminated Guardian desktop app (PID $($_.Id))." -ForegroundColor Gray
}

# Stop any background server listening on port 3000
try {
    $conn = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
    if ($conn -and $conn.OwningProcess) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "      + Stopped background security service (PID $($conn.OwningProcess))." -ForegroundColor Gray
    }
} catch {}

# 2. Remove Windows Autostart & Scheduled Tasks
Write-Host "[2/5] Removing autostart configuration..." -ForegroundColor White

# Remove Registry Startup Key
try {
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "GuardianSecurity" -ErrorAction SilentlyContinue
    Write-Host "      + Removed Windows startup registry key." -ForegroundColor Gray
} catch {}

# Remove Scheduled Task (if created)
$TaskName = "Guardian_BackgroundWorker"
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "      + Unregistered Scheduled Task '$TaskName'." -ForegroundColor Gray
} catch {}

# 3. Remove Desktop & Start Menu Shortcuts
Write-Host "[3/5] Removing shortcuts..." -ForegroundColor White

# Desktop shortcut
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$DesktopShortcut = Join-Path $DesktopPath "Guardian Security.lnk"
if (Test-Path $DesktopShortcut) {
    Remove-Item -Path $DesktopShortcut -Force -ErrorAction SilentlyContinue
    Write-Host "      + Removed Desktop shortcut." -ForegroundColor Gray
}

# Start Menu folder
$StartMenuPath = [Environment]::GetFolderPath("Programs")
$GuardianStartMenuDir = Join-Path $StartMenuPath "Guardian"
if (Test-Path $GuardianStartMenuDir) {
    Remove-Item -Path $GuardianStartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "      + Removed Start Menu folder." -ForegroundColor Gray
}

# 4. Remove Installed Program Files
Write-Host "[4/5] Removing program files..." -ForegroundColor White
$InstallPaths = @(
    "C:\Program Files\Guardian",
    (Join-Path $env:LOCALAPPDATA "Programs\Guardian")
)

foreach ($path in $InstallPaths) {
    if (Test-Path $path) {
        try {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "      + Cleaned directory: $path" -ForegroundColor Gray
        } catch {
            Write-Host "      ! Some files in $path could not be locked. They will be removed on reboot." -ForegroundColor Yellow
        }
    }
}

# 5. Clean up temporary AppData and WebView2 Cache
Write-Host "[5/5] Cleaning application cache..." -ForegroundColor White
$AppDataGuardian = Join-Path $env:LOCALAPPDATA "Guardian"
if (Test-Path $AppDataGuardian) {
    Remove-Item -Path $AppDataGuardian -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "      + Cleaned AppData cache." -ForegroundColor Gray
}

Write-Host ""
Write-Host "====================================================" -ForegroundColor Green
Write-Host "   GUARDIAN HAS BEEN COMPLETELY UNINSTALLED         " -ForegroundColor Green
Write-Host "====================================================" -ForegroundColor Green
Write-Host "All processes, autostart entries, shortcuts, and files"
Write-Host "have been cleanly removed from this laptop."
Write-Host ""
