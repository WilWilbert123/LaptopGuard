# =====================================================================
# MY LAPTOP GUARD - Windows Background Service Installer
# Registers a Windows Scheduled Task to run the background worker
# automatically at user login without opening a visible console window.
# =====================================================================

$TaskName = "MyLaptopGuard_BackgroundWorker"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path (Join-Path $ScriptDir "..")
$ServerScript = Join-Path $ProjectRoot "background\server.js"

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  MY LAPTOP GUARD - Background Service Setup        " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "Project directory: $ProjectRoot"
Write-Host "Entrypoint: $ServerScript"

# 1. Verify Node.js is installed
$NodePath = (Get-Command node.exe -ErrorAction SilentlyContinue).Source
if (-not $NodePath) {
    Write-Host "[ERROR] Node.js is not found in PATH! Please install Node.js LTS first." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Detected Node.js at: $NodePath" -ForegroundColor Green

# 2. Check Administrator privilege
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    Write-Host "[OK] Running with Administrator privileges. Task can be created with highest elevation." -ForegroundColor Green
    $RunLevel = "HighestAvailable"
} else {
    Write-Host "[INFO] Running as standard user. Task will be registered with standard user privileges." -ForegroundColor Yellow
    $RunLevel = "Limited"
}

# 3. Create Scheduled Task Action
# Uses wscript / powershell -WindowStyle Hidden to run completely in background
$Argument = "-WindowStyle Hidden -Command `"Set-Location '$ProjectRoot'; & '$NodePath' '$ServerScript'`""
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $Argument -WorkingDirectory $ProjectRoot

# 4. Trigger at User Logon
$Trigger = New-ScheduledTaskTrigger -AtLogOn

# 5. Settings: Don't stop on battery, restart on failure, allow start if on battery
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

# 6. Register Task
try {
    # Unregister if already exists
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -RunLevel $RunLevel -Description "My Laptop Guard Personal Background Worker" | Out-Null
    Write-Host "`n[SUCCESS] Scheduled Task '$TaskName' registered successfully!" -ForegroundColor Green
    Write-Host "The worker will automatically start whenever you log in to Windows."
    Write-Host "To start the task immediately in the background, run:"
    Write-Host "    Start-ScheduledTask -TaskName '$TaskName'" -ForegroundColor Cyan
    Write-Host "To remove the task, run scripts/uninstall-service.ps1"
} catch {
    Write-Host "[ERROR] Failed to register scheduled task: $_" -ForegroundColor Red
    exit 1
}
