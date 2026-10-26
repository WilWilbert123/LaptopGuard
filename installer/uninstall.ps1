# =====================================================================
# GUARDIAN - Uninstaller Script
# Stops the background service, unregisters scheduled tasks,
# removes shortcuts, and cleans up installation files.
# =====================================================================

[CmdletBinding()]
param(
    [switch]$PurgeData = $false
)

Write-Host "====================================================" -ForegroundColor Yellow
Write-Host "   GUARDIAN - Uninstallation Wizard                " -ForegroundColor Yellow
Write-Host "====================================================" -ForegroundColor Yellow
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AppDir = Resolve-Path (Join-Path $ScriptDir "..")

# 1. Stop background processes
Write-Host "[1/4] Stopping Guardian background processes..." -ForegroundColor White
$TaskName = "Guardian_BackgroundWorker"
try {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "[OK] Scheduled task '$TaskName' removed." -ForegroundColor Green
} catch {
    Write-Host "[INFO] No scheduled task found." -ForegroundColor Gray
}

# Stop any running node server on port 3000
try {
    $conn = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue
    if ($conn -and $conn.OwningProcess) {
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Stopped active Guardian server (PID $($conn.OwningProcess))." -ForegroundColor Green
    }
} catch {}

# 2. Remove Desktop and Start Menu Shortcuts
Write-Host "[2/4] Removing shortcuts..." -ForegroundColor White
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$DesktopShortcut = Join-Path $DesktopPath "Guardian Security.lnk"
if (Test-Path $DesktopShortcut) {
    Remove-Item -Path $DesktopShortcut -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Removed Desktop shortcut." -ForegroundColor Green
}

$StartMenuPath = [Environment]::GetFolderPath("Programs")
$GuardianStartMenuDir = Join-Path $StartMenuPath "Guardian"
if (Test-Path $GuardianStartMenuDir) {
    Remove-Item -Path $GuardianStartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Removed Start Menu shortcuts." -ForegroundColor Green
}

# 3. Handle Database / Logs
Write-Host "[3/4] Handling security telemetry history..." -ForegroundColor White
$DataDir = Join-Path $AppDir "data"
if ($PurgeData) {
    if (Test-Path $DataDir) {
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "[OK] Security database and history deleted." -ForegroundColor Green
    }
} else {
    Write-Host "[INFO] Telemetry database preserved at $DataDir (Run with -PurgeData to remove)." -ForegroundColor Gray
}

# 4. Completion
Write-Host "[4/4] Uninstallation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "====================================================" -ForegroundColor Yellow
Write-Host "   GUARDIAN HAS BEEN REMOVED                        " -ForegroundColor Yellow
Write-Host "====================================================" -ForegroundColor Yellow
Write-Host "Guardian background monitoring has been stopped and uninstalled."
Write-Host ""
