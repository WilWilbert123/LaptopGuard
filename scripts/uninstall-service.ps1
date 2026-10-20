# =====================================================================
# MY LAPTOP GUARD - Windows Background Service Uninstaller
# Unregisters the scheduled task and terminates any running worker.
# =====================================================================

$TaskName = "MyLaptopGuard_BackgroundWorker"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  MY LAPTOP GUARD - Removing Background Service     " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

try {
    # Stop task if running
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

    # Unregister task
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "[SUCCESS] Task '$TaskName' has been unregistered and removed." -ForegroundColor Green
} catch {
    Write-Host "[INFO] Scheduled task '$TaskName' was not found or was already removed." -ForegroundColor Yellow
}

# Optional: stop any orphan node process running background/server.js
$Procs = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like "*background/server.js*" -or $_.CommandLine -like "*background\server.js*" }
if ($Procs) {
    foreach ($p in $Procs) {
        Write-Host "Stopping running worker process (PID $($p.ProcessId))..."
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[OK] Worker processes terminated." -ForegroundColor Green
} else {
    Write-Host "[INFO] No running worker process found." -ForegroundColor Gray
}

Write-Host "`nUninstallation complete." -ForegroundColor Green
