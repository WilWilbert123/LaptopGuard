@echo off
:: =====================================================================
:: GUARDIAN - One-Click Windows Installer Launcher
:: Prompts for Administrator elevation (UAC) and runs install.ps1
:: =====================================================================

title Guardian - Personal Laptop Security Setup
cd /d "%~dp0"

:: Check for Administrator permissions
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :RunInstall
) else (
    goto :Elevate
)

:Elevate
echo Requesting administrative privileges to install Guardian background service...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
exit /b

:RunInstall
echo ====================================================
echo    GUARDIAN - Personal Laptop Security Installer   
echo ====================================================
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Installation encountered an error.
    pause
    exit /b %errorLevel%
)

echo.
echo Press any key to close this installer window...
pause >nul
exit /b 0
