# Guardian Installer & Deployment Guide

This directory contains the automated installation suite for **Guardian: Personal Laptop Security & Threat Monitor**.

---

## 🚀 Standalone C# Installer (Recommended - No Source Code Required)

Guardian is compiled into a standalone Windows installer: **[`dist/Guardian-Setup.exe`](file:///c:/Users/MIS-WILBERT/Desktop/bgworker/dist/Guardian-Setup.exe)**.

### Features of the C# Standalone Installer:
- **No Source Code Needed**: Distribute only `Guardian-Setup.exe`.
- **No Node.js Required**: The runtime is bundled automatically.
- **No External Browser**: Launches inside a native C# Windows Desktop application window with custom dark theme and system tray icon.
- **No `127.0.0.1` Connection Errors**: The C# launcher waits for the background telemetry engine to be 100% active before presenting the dashboard.
- **One-Click Wizard**: Creates Desktop shortcuts, Start Menu entries, and autostart on Windows login.

### How to Install:
1. Double-click **`Guardian-Setup.exe`** (located in `dist/Guardian-Setup.exe`).
2. Choose your installation folder (defaults to `C:\Program Files\Guardian`).
3. Click **Install**.
4. Check **Launch Guardian Security now** and click **Finish**.

---

## 📦 How to Rebuild the Standalone Installer

If you ever make changes and want to generate a new `Guardian-Setup.exe`:

```powershell
powershell -ExecutionPolicy Bypass -File installer/build-package.ps1
```

This compiles:
1. `GuardianApp/Guardian.csproj` (C# WinForms + WebView2 desktop application).
2. The bundled background engine with portable runtime.
3. `GuardianInstaller/GuardianInstaller.csproj` into a self-contained **`dist/Guardian-Setup.exe`**.

---

## 🗑️ Uninstallation

To remove Guardian:
1. Right-click the Guardian tray icon and click **Exit Guardian**.
2. Delete the installation folder (or use Windows Settings > Installed Apps).
