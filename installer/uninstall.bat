@echo off
:: =====================================================================
:: GUARDIAN - 1-Click Complete Uninstaller
:: Self-contained batch file with embedded PowerShell uninstaller.
:: Automatically requests Administrator elevation and cleans everything.
:: =====================================================================

title Uninstall Guardian - Personal Laptop Security
cd /d "%~dp0"

:: Check for Administrator permissions
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges to uninstall Guardian...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

echo ====================================================
echo    UNINSTALL GUARDIAN - Personal Laptop Security   
echo ====================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'SilentlyContinue';" ^
    "Write-Host '[1/5] Terminating Guardian processes...' -ForegroundColor Cyan;" ^
    "Get-Process -Name 'Guardian' -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue; Write-Host ('      + Stopped Guardian (PID ' + $_.Id + ')') };" ^
    "try { $c = Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue; if ($c -and $c.OwningProcess) { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue; Write-Host ('      + Stopped Background Engine (PID ' + $c.OwningProcess + ')') } } catch {};" ^
    "Write-Host '[2/5] Removing Windows autostart configuration...' -ForegroundColor Cyan;" ^
    "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'GuardianSecurity' -ErrorAction SilentlyContinue;" ^
    "Unregister-ScheduledTask -TaskName 'Guardian_BackgroundWorker' -Confirm:$false -ErrorAction SilentlyContinue;" ^
    "Write-Host '[3/5] Removing Desktop and Start Menu shortcuts...' -ForegroundColor Cyan;" ^
    "$desk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Guardian Security.lnk';" ^
    "if (Test-Path $desk) { Remove-Item -Path $desk -Force -ErrorAction SilentlyContinue; Write-Host '      + Removed Desktop shortcut' };" ^
    "$menu = Join-Path ([Environment]::GetFolderPath('Programs')) 'Guardian';" ^
    "if (Test-Path $menu) { Remove-Item -Path $menu -Recurse -Force -ErrorAction SilentlyContinue; Write-Host '      + Removed Start Menu folder' };" ^
    "Write-Host '[4/5] Deleting installed files and folders...' -ForegroundColor Cyan;" ^
    "$targets = @('C:\Program Files\Guardian', 'C:\Program Files\Guardiannew', (Join-Path $env:LOCALAPPDATA 'Programs\Guardian'), (Join-Path $env:LOCALAPPDATA 'Programs\Guardiannew'));" ^
    "foreach ($t in $targets) { if (Test-Path $t) { Remove-Item -Path $t -Recurse -Force -ErrorAction SilentlyContinue; Write-Host ('      + Deleted ' + $t) } };" ^
    "Write-Host '[5/5] Cleaning application cache...' -ForegroundColor Cyan;" ^
    "$cache = Join-Path $env:LOCALAPPDATA 'Guardian';" ^
    "if (Test-Path $cache) { Remove-Item -Path $cache -Recurse -Force -ErrorAction SilentlyContinue; Write-Host '      + Cleaned AppData cache' };" ^
    "Write-Host '';" ^
    "Write-Host '====================================================' -ForegroundColor Green;" ^
    "Write-Host '   GUARDIAN HAS BEEN COMPLETELY REMOVED' -ForegroundColor Green;" ^
    "Write-Host '====================================================' -ForegroundColor Green;"

echo.
echo Press any key to close this window...
pause >nul
exit /b 0
