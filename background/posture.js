/**
 * MY LAPTOP GUARD - Security Posture Evaluator (posture.js)
 * Evaluates core Windows security configurations to generate a 0-100 Laptop Health Score.
 * Every deduction is itemized with a plain-English explanation and Windows settings path.
 * Read-only; never applies automatic modifications.
 */

const db = require('./database');
const psHost = require('./ps-host');

class SecurityPostureEvaluator {
  constructor() {
    this.lastEvaluatedUtc = null;
    this.latestSnapshot = null;
  }

  /**
   * Executes PowerShell assessment script to query system security states
   */
  async evaluate() {
    const start = Date.now();
    try {
      const script = `
        $uac = Get-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -ErrorAction SilentlyContinue
        $smb1 = Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name SMB1 -ErrorAction SilentlyContinue
        $smartScreen = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' -Name SmartScreenEnabled -ErrorAction SilentlyContinue
        $ts = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue
        $nla = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue
        $ra = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Remote Assistance' -ErrorAction SilentlyContinue
        $guest = Get-CimInstance Win32_UserAccount -Filter "Name='Guest'" -ErrorAction SilentlyContinue
        $secBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        $tpm = Get-Tpm -ErrorAction SilentlyContinue
        $fw = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled

        [PSCustomObject]@{
          UacEnabled = if ($uac) { $uac.EnableLUA } else { $null }
          Smb1Enabled = if ($smb1) { $smb1.SMB1 } else { 0 }
          SmartScreen = if ($smartScreen) { $smartScreen.SmartScreenEnabled } else { $null }
          RdpDeny = if ($ts) { $ts.fDenyTSConnections } else { $null }
          RdpNla = if ($nla) { $nla.UserAuthentication } else { $null }
          RemoteAssistance = if ($ra) { $ra.fAllowToGetHelp } else { $null }
          GuestDisabled = if ($guest) { $guest.Disabled } else { $true }
          SecureBoot = $secBoot
          TpmPresent = if ($tpm) { $tpm.TpmPresent } else { $null }
          TpmReady = if ($tpm) { $tpm.TpmReady } else { $null }
          FirewallProfiles = $fw
        }
      `;

      const raw = await psHost.execute(script, { timeoutMs: 9000, asJson: true }) || {};

      // Get latest Defender telemetry from database or memory
      const latestHealth = db.getLatestHealth();
      let defenderStatus = {};
      try {
        const defPs = `
          Get-MpComputerStatus -ErrorAction SilentlyContinue |
          Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IsTamperProtected, DefenderSignaturesOutOfDate
        `;
        const defRes = await psHost.execute(defPs, { timeoutMs: 6000, asJson: true });
        if (defRes) defenderStatus = defRes;
      } catch (e) {}

      let score = 100;
      const deductions = [];
      const checks = {};

      // 1. Antivirus Active (10 pts)
      const avActive = defenderStatus.AntivirusEnabled !== false;
      checks.antivirusActive = avActive;
      if (!avActive) {
        score -= 10;
        deductions.push({
          category: 'Antivirus',
          title: 'Antivirus Protection Is Disabled',
          points: 10,
          current: 'Disabled',
          recommendation: 'Enable Microsoft Defender Antivirus',
          settingsPath: 'Settings > Privacy & security > Windows Security > Virus & threat protection',
          explanation: 'No active antivirus engine is safeguarding this computer against malware.'
        });
      }

      // 2. Real-Time Protection (10 pts)
      const rtpActive = defenderStatus.RealTimeProtectionEnabled !== false;
      checks.realTimeProtection = rtpActive;
      if (!rtpActive) {
        score -= 10;
        deductions.push({
          category: 'Real-Time Protection',
          title: 'Real-Time File & Process Monitoring Disabled',
          points: 10,
          current: 'Disabled',
          recommendation: 'Enable Real-time protection',
          settingsPath: 'Settings > Privacy & security > Windows Security > Virus & threat protection settings',
          explanation: 'Files and programs are not being scanned dynamically as they are opened or downloaded.'
        });
      }

      // 3. Tamper Protection (10 pts)
      const tamperActive = defenderStatus.IsTamperProtected !== false;
      checks.tamperProtection = tamperActive;
      if (!tamperActive) {
        score -= 10;
        deductions.push({
          category: 'Tamper Protection',
          title: 'Defender Tamper Protection Off',
          points: 10,
          current: 'Off',
          recommendation: 'Turn on Tamper Protection',
          settingsPath: 'Settings > Privacy & security > Windows Security > Virus & threat protection settings',
          explanation: 'Malware or rogue scripts can disable your antivirus protection without authorization.'
        });
      }

      // 4. Antivirus Signatures Fresh (5 pts)
      const sigsOutOfDate = defenderStatus.DefenderSignaturesOutOfDate === true;
      checks.signaturesFresh = !sigsOutOfDate;
      if (sigsOutOfDate) {
        score -= 5;
        deductions.push({
          category: 'Security Intelligence',
          title: 'Antivirus Signatures Out of Date',
          points: 5,
          current: 'Out of Date',
          recommendation: 'Update security intelligence definitions',
          settingsPath: 'Settings > Privacy & security > Windows Security > Virus & threat protection updates',
          explanation: 'Your antivirus definitions are outdated, leaving your laptop vulnerable to recent threats.'
        });
      }

      // 5. Windows Firewall Profiles (15 pts)
      let fwDisabled = false;
      if (Array.isArray(raw.FirewallProfiles)) {
        fwDisabled = raw.FirewallProfiles.some(p => p.Enabled === false);
      }
      checks.firewallEnabled = !fwDisabled;
      if (fwDisabled) {
        score -= 15;
        deductions.push({
          category: 'Firewall',
          title: 'One or More Windows Firewall Profiles Disabled',
          points: 15,
          current: 'Partially Disabled',
          recommendation: 'Enable Domain, Private, and Public Firewall Profiles',
          settingsPath: 'Settings > Privacy & security > Windows Security > Firewall & network protection',
          explanation: 'A disabled firewall profile exposes your laptop to unauthorized incoming network probes.'
        });
      }

      // 6. User Account Control (UAC) (10 pts)
      const uacActive = raw.UacEnabled === 1 || raw.UacEnabled === null; // null on non-admin
      checks.uacEnabled = uacActive;
      if (raw.UacEnabled === 0) {
        score -= 10;
        deductions.push({
          category: 'Account Security',
          title: 'User Account Control (UAC) Disabled',
          points: 10,
          current: 'Disabled (Never Notify)',
          recommendation: 'Set UAC slider to default or highest level',
          settingsPath: 'Control Panel > User Accounts > Change User Account Control settings',
          explanation: 'Any process can elevate to administrator permissions without prompting you.'
        });
      }

      // 7. Secure Boot (10 pts)
      const secBootActive = raw.SecureBoot === true;
      checks.secureBoot = secBootActive;
      if (raw.SecureBoot === false) {
        score -= 10;
        deductions.push({
          category: 'Firmware Security',
          title: 'UEFI Secure Boot Disabled',
          points: 10,
          current: 'Disabled',
          recommendation: 'Enable Secure Boot in your laptop BIOS/UEFI settings',
          settingsPath: 'UEFI BIOS Firmware Settings > Security > Secure Boot',
          explanation: 'Secure Boot ensures that only trusted bootloaders and drivers can execute during laptop startup.'
        });
      }

      // 8. TPM Ready (5 pts)
      const tpmActive = raw.TpmPresent === true && raw.TpmReady === true;
      checks.tpmReady = tpmActive;
      if (raw.TpmPresent === false || raw.TpmReady === false) {
        score -= 5;
        deductions.push({
          category: 'Hardware Security',
          title: 'TPM Security Module Inactive',
          points: 5,
          current: 'Not Ready',
          recommendation: 'Enable TPM 2.0 / PTT in laptop BIOS settings',
          settingsPath: 'UEFI BIOS Settings > Security > Trusted Platform Module',
          explanation: 'Hardware security chip provides hardware-backed key storage and device identity.'
        });
      }

      // 9. Remote Desktop Exposure (10 pts)
      // If RDP is enabled (fDenyTS == 0), require NLA (userAuth == 1)
      const rdpExposed = raw.RdpDeny === 0 && raw.RdpNla !== 1;
      checks.rdpSecure = !rdpExposed;
      if (rdpExposed) {
        score -= 10;
        deductions.push({
          category: 'Remote Access',
          title: 'Remote Desktop Allowed Without Network Level Authentication (NLA)',
          points: 10,
          current: 'RDP Enabled (Legacy / No NLA)',
          recommendation: 'Enable Network Level Authentication or turn off Remote Desktop',
          settingsPath: 'Settings > System > Remote Desktop',
          explanation: 'RDP without NLA allows remote users to connect before authenticating credentials.'
        });
      }

      // 10. SMBv1 Protocol (5 pts)
      const smb1Active = raw.Smb1Enabled === 1;
      checks.smb1Disabled = !smb1Active;
      if (smb1Active) {
        score -= 5;
        deductions.push({
          category: 'Network Protocol',
          title: 'Insecure SMBv1 Protocol Is Enabled',
          points: 5,
          current: 'Enabled',
          recommendation: 'Disable SMB 1.0/CIFS File Sharing Support in Windows Features',
          settingsPath: 'Control Panel > Programs and Features > Turn Windows features on or off',
          explanation: 'SMBv1 is an obsolete protocol known for severe remote code execution vulnerabilities (EternalBlue).'
        });
      }

      // 11. Guest Account (5 pts)
      const guestDisabled = raw.GuestDisabled !== false;
      checks.guestDisabled = guestDisabled;
      if (!guestDisabled) {
        score -= 5;
        deductions.push({
          category: 'Account Security',
          title: 'Built-in Guest Account Is Active',
          points: 5,
          current: 'Enabled',
          recommendation: 'Disable the Guest user account',
          settingsPath: 'Computer Management > Local Users and Groups > Users > Guest > Account is disabled',
          explanation: 'An active Guest account enables anonymous local access without a unique password.'
        });
      }

      const clampedScore = Math.max(0, Math.min(100, score));
      let grade = 'F';
      if (clampedScore >= 90) grade = 'A';
      else if (clampedScore >= 80) grade = 'B';
      else if (clampedScore >= 70) grade = 'C';
      else if (clampedScore >= 60) grade = 'D';

      const snapshot = {
        timestampUtc: new Date().toISOString(),
        score: clampedScore,
        grade,
        deductions,
        checks,
        durationMs: Date.now() - start
      };

      this.latestSnapshot = snapshot;
      this.lastEvaluatedUtc = snapshot.timestampUtc;

      // Save posture snapshot to SQLite
      db.recordPostureSnapshot(snapshot);
      db.recordHealth('PostureEvaluator', 'OK', snapshot.durationMs, `Posture Score: ${clampedScore} (${grade})`);

      return snapshot;
    } catch (err) {
      db.recordHealth('PostureEvaluator', 'DEGRADED', Date.now() - start, err.message);
      return null;
    }
  }

  getSnapshot() {
    if (this.latestSnapshot) return this.latestSnapshot;
    const dbSnap = db.getLatestPostureSnapshot();
    if (dbSnap) return dbSnap;

    return {
      timestampUtc: new Date().toISOString(),
      score: 100,
      grade: 'A',
      deductions: [],
      checks: {},
      durationMs: 0
    };
  }
}

// Singleton instance
const postureEvaluator = new SecurityPostureEvaluator();
module.exports = postureEvaluator;
module.exports.SecurityPostureEvaluator = SecurityPostureEvaluator;
