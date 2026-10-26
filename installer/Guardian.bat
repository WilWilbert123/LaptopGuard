@echo off
:: =====================================================================
:: GUARDIAN - Native Desktop Application Window Launcher
:: =====================================================================
cd /d "%~dp0"
start "" wscript.exe "%~dp0Guardian-Launcher.vbs" --open
exit /b 0
