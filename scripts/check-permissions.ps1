# =====================================================================
# MY LAPTOP GUARD - Permissions & Environment Diagnostics
# Tests all Windows subsystem access: Defender, Firewall, Port binding, Admin
# =====================================================================

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host "  MY LAPTOP GUARD - System Diagnostics              " -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan

# 1. Administrator Check
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($IsAdmin) {
    Write-Host "[OK] Administrator Privileges: ELEVATED (Full firewall control enabled)" -ForegroundColor Green
} else {
    Write-Host "[WARN] Administrator Privileges: STANDARD USER (Read-only firewall inspection. Creating firewall rules requires elevation)" -ForegroundColor Yellow
}

# 2. Node.js Check
$NodeVer = node -v 2>$null
if ($NodeVer) {
    Write-Host "[OK] Node.js Version: $NodeVer" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Node.js not detected in PATH!" -ForegroundColor Red
}

# 3. Windows Defender Telemetry Check
try {
    $Def = Get-MpComputerStatus -ErrorAction Stop
    Write-Host "[OK] Windows Defender WMI interface: ACCESSIBLE" -ForegroundColor Green
    Write-Host "     - Antivirus Enabled: $($Def.AntivirusEnabled)"
    Write-Host "     - Real-Time Protection: $($Def.RealTimeProtectionEnabled)"
    Write-Host "     - Signature Version: $($Def.AntivirusSignatureVersion)"
} catch {
    Write-Host "[WARN] Windows Defender WMI interface returned: $_" -ForegroundColor Yellow
    Write-Host "     (If a 3rd party antivirus is installed, Defender may be passive)"
}

# 4. Windows Firewall Subsystem Check
try {
    $FwTest = netsh advfirewall show currentprofile
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Windows Firewall netsh interface: OPERATIONAL" -ForegroundColor Green
    } else {
        Write-Host "[WARN] netsh advfirewall returned code $LASTEXITCODE" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[ERROR] Windows Firewall interface inaccessible: $_" -ForegroundColor Red
}

# 5. Port 3000 Availability Check
$PortInUse = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue
if ($PortInUse) {
    Write-Host "[INFO] Port 3000 is currently active (PID: $($PortInUse[0].OwningProcess))" -ForegroundColor Cyan
} else {
    Write-Host "[OK] Port 3000 is available for dashboard binding." -ForegroundColor Green
}

Write-Host "`nDiagnostics complete." -ForegroundColor Cyan
