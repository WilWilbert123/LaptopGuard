# Guardian Installer & Deployment Guide

This directory contains the automated installation suite for **Guardian: Personal Laptop Security & Threat Monitor**.

---

## 🚀 Quick Install on Any Windows Laptop

### Option 1: Direct One-Click Install (Recommended)
1. Extract or open the Guardian folder on the target laptop.
2. Right-click **`install.bat`** and click **Run as administrator** (or double-click and accept the UAC prompt).
3. The installer will:
   - Copy Guardian to `C:\Program Files\Guardian` (or `%LOCALAPPDATA%\Programs\Guardian`).
   - Bundle/verify the Node.js runtime.
   - Register a Windows Scheduled Task (`Guardian_BackgroundWorker`) that starts Guardian silently in the background on every Windows login.
   - Create a **Guardian Security** desktop shortcut.
   - Create a Start Menu entry under `Guardian`.
   - Start the background monitor and open the live dashboard in your default browser.

---

## 📦 How to Create a Distributable Package for Another Laptop

To copy Guardian to a coworker's or family member's laptop via USB drive:

1. Open PowerShell in this project directory:
   ```powershell
   powershell -ExecutionPolicy Bypass -File installer/build-package.ps1
   ```
2. This creates:
   ```
   dist/Guardian-v1.0.0-Windows.zip
   ```
3. Put this ZIP on a USB stick or share it.
4. On the other laptop, extract the ZIP and double-click **`Install-Guardian.bat`**.

---

## 🗑️ Uninstallation

To remove Guardian completely:
1. Double-click **`installer/uninstall.bat`** (or use the Start Menu shortcut `Uninstall Guardian`).
2. The uninstaller will:
   - Terminate any running background Guardian processes.
   - Remove the Windows Scheduled Task.
   - Remove Desktop and Start Menu shortcuts.
   - Stop background monitoring cleanly.

---

## ⚙️ File Manifest

| File | Purpose |
| :--- | :--- |
| **`install.bat`** | Double-clickable batch wrapper with UAC elevation prompt |
| **`install.ps1`** | Primary PowerShell installer script |
| **`uninstall.bat`** | Double-clickable uninstaller wrapper |
| **`uninstall.ps1`** | Primary uninstaller script |
| **`Guardian-Launcher.vbs`** | Silent VBScript launcher (prevents black console window) |
| **`guardian-setup.iss`** | Inno Setup compiler script (generates `Guardian-Setup.exe`) |
| **`build-package.ps1`** | Packager script to produce `dist/Guardian-v1.0.0-Windows.zip` |
