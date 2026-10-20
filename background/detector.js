/**
 * MY LAPTOP GUARD - Security Detection Engine
 * Evidence-based rules identifying suspicious process behaviors, LOLBin network usage,
 * unauthorized remote access, persistence anomalies, and correlated indicators.
 */

// Well-known Living-off-the-Land Binaries (LOLBins) that rarely need direct internet connections
const LOLBINS = new Set([
  'cmd.exe',
  'powershell.exe',
  'pwsh.exe',
  'wscript.exe',
  'cscript.exe',
  'mshta.exe',
  'rundll32.exe',
  'regsvr32.exe',
  'certutil.exe',
  'bitsadmin.exe',
  'vssadmin.exe',
  'schtasks.exe'
]);

// Known remote access and support tools
const REMOTE_TOOLS = new Map([
  ['teamviewer.exe', 'TeamViewer Remote Access'],
  ['anydesk.exe', 'AnyDesk Remote Desktop'],
  ['vncviewer.exe', 'VNC Client/Server'],
  ['winvnc.exe', 'UltraVNC / RealVNC Server'],
  ['rustdesk.exe', 'RustDesk Remote Control'],
  ['screenconnect.clientservice.exe', 'ConnectWise ScreenConnect'],
  ['logmein.exe', 'LogMeIn Remote Access'],
  ['remotedesktop.exe', 'Chrome Remote Desktop / RDP App']
]);

// High-risk listening ports
const SUSPICIOUS_LISTEN_PORTS = new Map([
  [3389, { name: 'RDP (Remote Desktop Protocol)', risk: 'HIGH' }],
  [4444, { name: 'Metasploit Default Listener', risk: 'CRITICAL' }],
  [5900, { name: 'VNC Default Server Port', risk: 'HIGH' }],
  [23,   { name: 'Telnet (Unencrypted Remote Shell)', risk: 'HIGH' }],
  [1337, { name: 'Classic Trojan / Backdoor Port', risk: 'HIGH' }],
  [6667, { name: 'IRC (Potential Botnet C2 Channel)', risk: 'MEDIUM' }]
]);

// Safe / common system processes communicating on internet
const SYSTEM_ALLOWLIST = new Set([
  'system',
  'svchost.exe',
  'explorer.exe',
  'msedge.exe',
  'chrome.exe',
  'firefox.exe',
  'brave.exe',
  'opera.exe',
  'onedrive.exe',
  'teams.exe',
  'ms-teams.exe',
  'spotify.exe',
  'code.exe',
  'antigravity ide.exe'
]);

class SecurityDetector {
  constructor() {
    // Fingerprint -> timestamp ms for alert deduplication
    this.suppressionMap = new Map();
    this.cooldownMs = 10 * 60 * 1000; // 10 minutes
  }

  /**
   * Helper to determine if an IP is a local / private / loopback address
   */
  isPrivateOrLocalIp(ip) {
    if (!ip || ip === '*' || ip === '0.0.0.0' || ip === '::' || ip === '127.0.0.1' || ip === '::1') {
      return true;
    }
    // IPv4 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) {
      return true;
    }
    if (ip.startsWith('172.')) {
      const parts = ip.split('.');
      const second = parseInt(parts[1], 10);
      if (second >= 16 && second <= 31) return true;
    }
    // Link-local IPv6 (fe80::)
    if (ip.toLowerCase().startsWith('fe80:')) return true;

    return false;
  }

  /**
   * Checks if an executable path is located in suspicious or user-writable temp areas
   */
  isSuspiciousPath(exePath) {
    if (!exePath) return false;
    const lower = exePath.toLowerCase();

    // AppData\Local\Temp or Windows\Temp
    if (lower.includes('\\temp\\') || lower.includes('\\tmp\\')) return true;

    // Users\Public (often used by droppers because all users can write to it)
    if (lower.includes('c:\\users\\public\\') || lower.includes('\\users\\public\\')) return true;

    // Downloads folder executing outbound connection
    if (lower.includes('\\downloads\\')) return true;

    // Masquerading Windows system binaries running outside System32/SysWOW64
    const sys32Binaries = ['svchost.exe', 'csrss.exe', 'smss.exe', 'lsass.exe', 'wininit.exe', 'services.exe'];
    for (const bin of sys32Binaries) {
      if (lower.endsWith('\\' + bin)) {
        if (!lower.includes('\\system32\\') && !lower.includes('\\syswow64\\')) {
          return true; // Fake system binary!
        }
      }
    }

    return false;
  }

  /**
   * Evaluates an individual network connection against security detection rules
   */
  evaluateConnection(conn) {
    const findings = [];
    const procNameLower = (conn.processName || '').toLowerCase();
    const exePath = conn.processPath || '';
    const remoteIp = conn.remoteIp || '';
    const remotePort = conn.remotePort || 0;
    const localPort = conn.localPort || 0;
    const isPrivate = this.isPrivateOrLocalIp(remoteIp);

    // Rule 1: Suspicious Executable Location with Active External Connection
    if (exePath && !isPrivate && this.isSuspiciousPath(exePath)) {
      findings.push({
        ruleId: 'RULE_SUSP_PATH',
        title: 'Network Socket from Suspicious File Path',
        severity: 'HIGH',
        confidence: 'HIGH',
        processName: conn.processName,
        pid: conn.pid,
        remoteIp: remoteIp,
        explanation: `Process "${conn.processName}" is executing from a user-writable directory (${exePath}) and established an external connection to ${remoteIp}:${remotePort}. Malware droppers frequently run from Temp, Public, or Downloads directories.`,
        evidence: [
          `Process: ${conn.processName} (PID ${conn.pid})`,
          `Executable Path: ${exePath}`,
          `Destination: ${remoteIp}:${remotePort} (${conn.protocol})`,
          `State: ${conn.state}`
        ],
        remediation: 'Inspect the file in Windows Explorer, verify digital signatures with PowerShell Get-AuthenticodeSignature, or block the destination IP with Windows Firewall.',
        disclaimer: 'Evidence-based heuristic indicator. Not all software running from AppData or Temp is malicious (some software updaters run from Temp).'
      });
    }

    // Rule 2: Living-off-the-Land Binary (LOLBin) establishing external connection
    if (LOLBINS.has(procNameLower) && !isPrivate && conn.state === 'ESTABLISHED') {
      findings.push({
        ruleId: 'RULE_LOLBIN_NET',
        title: `Unusual Network Activity from Script/System Tool (${conn.processName})`,
        severity: 'HIGH',
        confidence: 'HIGH',
        processName: conn.processName,
        pid: conn.pid,
        remoteIp: remoteIp,
        explanation: `System command interpreter or script engine "${conn.processName}" has established an active outbound internet connection to ${remoteIp}:${remotePort}. Living-off-the-land binaries (LOLBins) are often abused by malicious scripts to retrieve secondary payloads or communicate with C2 servers.`,
        evidence: [
          `Command tool: ${conn.processName} (PID ${conn.pid})`,
          `Path: ${exePath || 'Standard System Path'}`,
          `Remote Endpoint: ${remoteIp}:${remotePort}`,
          `Protocol: ${conn.protocol} (${conn.state})`
        ],
        remediation: 'Investigate the command line arguments of this process using Task Manager or PowerShell. If unauthorized, terminate the process and block the IP.',
        disclaimer: 'System tools may occasionally connect for administrative tasks (e.g. PowerShell downloading modules or running Invoke-WebRequest).'
      });
    }

    // Rule 3: Remote Control Software Active Socket
    if (REMOTE_TOOLS.has(procNameLower)) {
      const toolDesc = REMOTE_TOOLS.get(procNameLower);
      findings.push({
        ruleId: 'RULE_REMOTE_TOOL',
        title: `Remote Access Tool Active (${toolDesc})`,
        severity: 'MEDIUM',
        confidence: 'HIGH',
        processName: conn.processName,
        pid: conn.pid,
        remoteIp: remoteIp,
        explanation: `Remote control application "${toolDesc}" is active and communicating over ${conn.protocol} to ${remoteIp}:${remotePort}. While commonly used for legitimate remote work, unauthorized or unrecognized remote access software presents a severe remote-control takeover risk.`,
        evidence: [
          `Tool: ${toolDesc}`,
          `Process: ${conn.processName} (PID ${conn.pid})`,
          `Remote Socket: ${remoteIp}:${remotePort}`,
          `State: ${conn.state}`
        ],
        remediation: 'Verify whether you explicitly initiated or authorized this remote desktop session. If not, close the application immediately.',
        disclaimer: 'Legitimate remote desktop tools are routinely used for support. Never assume a remote tool is malicious without context.'
      });
    }

    // Rule 4: Suspicious Listening Ports on all network interfaces
    if (conn.state === 'LISTENING' && (conn.localIp === '0.0.0.0' || conn.localIp === '::')) {
      if (SUSPICIOUS_LISTEN_PORTS.has(localPort)) {
        const portInfo = SUSPICIOUS_LISTEN_PORTS.get(localPort);
        findings.push({
          ruleId: 'RULE_SUSP_LISTENING',
          title: `Sensitive Listening Port Open (${portInfo.name} on Port ${localPort})`,
          severity: portInfo.risk,
          confidence: 'HIGH',
          processName: conn.processName,
          pid: conn.pid,
          remoteIp: null,
          explanation: `Your laptop is listening for incoming network connections on port ${localPort} (${portInfo.name}) on all network interfaces (0.0.0.0 / ::). Anyone on your local Wi-Fi or network can attempt connection.`,
          evidence: [
            `Port: ${localPort} (${portInfo.name})`,
            `Bound Address: ${conn.localIp}:${localPort}`,
            `Owning Process: ${conn.processName || 'System'} (PID ${conn.pid})`
          ],
          remediation: 'Verify if this service is required. If Remote Desktop is not needed, disable Remote Desktop in Windows Settings.',
          disclaimer: 'Port usage depends on enabled Windows features. RDP port 3389 is expected if Remote Desktop is intentionally turned on.'
        });
      }
    }

    return findings;
  }

  /**
   * Evaluates Startup persistence items for anomalous entries
   */
  evaluateStartupItem(item) {
    const findings = [];
    if (!item || !item.command) return findings;

    const cmdLower = item.command.toLowerCase();

    // Check if startup points to Temp, Public, or Downloads
    const inTemp = cmdLower.includes('\\temp\\') || cmdLower.includes('\\tmp\\');
    const inPublic = cmdLower.includes('\\users\\public\\');
    const inDownloads = cmdLower.includes('\\downloads\\');

    // Check for suspicious script execution flags
    const hasScriptFlags = cmdLower.includes('-enc ') ||
                           cmdLower.includes('-encodedcommand') ||
                           cmdLower.includes('-windowstyle hidden') ||
                           cmdLower.includes('-w hidden') ||
                           cmdLower.includes('bypass') ||
                           cmdLower.includes('wscript.exe') ||
                           cmdLower.includes('mshta.exe');

    if (inTemp || inPublic || inDownloads || hasScriptFlags) {
      findings.push({
        ruleId: 'RULE_STARTUP_PERSISTENCE',
        title: `Suspicious Startup Entry Detected: ${item.name}`,
        severity: hasScriptFlags ? 'HIGH' : 'MEDIUM',
        confidence: 'HIGH',
        processName: item.name,
        pid: null,
        remoteIp: null,
        explanation: `A startup persistence item "${item.name}" was found configured to launch automatically with Windows from a user-writable location or with concealed script flags.`,
        evidence: [
          `Startup Name: ${item.name}`,
          `Location: ${item.location}`,
          `Command: ${item.command}`,
          `Indicators: ${[inTemp && 'Temp directory', inPublic && 'Public directory', inDownloads && 'Downloads directory', hasScriptFlags && 'Hidden/Encoded script execution'].filter(Boolean).join(', ')}`
        ],
        remediation: 'Inspect this startup entry in Task Manager (Startup tab) or autoruns. Disable it if not recognized.',
        disclaimer: 'Some legacy setup programs temporarily place updaters in Temp or Startup.'
      });
    }

    return findings;
  }

  /**
   * Filters findings to suppress duplicates within the cooldown window
   */
  deduplicateFindings(rawFindings) {
    const now = Date.now();
    const uniqueFindings = [];

    // Clean up expired suppression entries periodically
    if (this.suppressionMap.size > 1000) {
      for (const [key, ts] of this.suppressionMap.entries()) {
        if (now - ts > this.cooldownMs) {
          this.suppressionMap.delete(key);
        }
      }
    }

    for (const f of rawFindings) {
      const fingerprint = `${f.ruleId}_${f.pid || 0}_${f.remoteIp || 'none'}_${f.processName || 'none'}`;
      const lastSeen = this.suppressionMap.get(fingerprint);

      if (!lastSeen || (now - lastSeen > this.cooldownMs)) {
        this.suppressionMap.set(fingerprint, now);
        f.fingerprint = fingerprint;
        uniqueFindings.push(f);
      }
    }

    return uniqueFindings;
  }
}

module.exports = new SecurityDetector();
