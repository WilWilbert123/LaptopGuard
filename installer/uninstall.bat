@echo off
:: =====================================================================
:: GUARDIAN - One-Click Windows Uninstaller Launcher
:: Prompts for Administrator elevation (UAC) and runs uninstall.ps1
:: =====================================================================

title Uninstall Guardian - Personal Laptop Security
cd /d "%~dp0"

:: Check for Administrator permissions
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :RunUninstall
) else (
    goto :Elevate
)

:Elevate
echo Requesting administrative privileges to remove Guardian background service...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
exit /b

:RunUninstall
echo ====================================================
echo    UNINSTALL GUARDIAN - Personal Laptop Security   
echo ====================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"

echo.
echo Press any key to close this window...
pause >nul
exit /b 0
