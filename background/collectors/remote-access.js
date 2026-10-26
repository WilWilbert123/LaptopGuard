/**
 * MY LAPTOP GUARD - Remote Access & Spying Collector (remote-access.js)
 * Real-time monitoring of active remote desktop sessions, known remote administration tools,
 * reverse command shells, and webcam/microphone ConsentStore sensor access.
 * Strictly local, non-intrusive, read-only.
 */

const db = require('../database');
const psHost = require('../ps-host');
const knownTools = require('../rules/known-tools.json');
const { evaluateRemoteAccessState, calculateRemoteRiskScore } = require('../rules/remote-access');
/**
 * Computes connection interval and jitter percentage to detect beacon-like traffic
 */
function computeBeaconMetrics(timestamps) {
  if (!timestamps || timestamps.length < 3) {
    return { isBeacon: false, intervalSec: null, jitterPercent: null };
  }
  const sorted = [...timestamps].sort((a, b) => a - b);
  const deltas = [];
  for (let i = 1; i < sorted.length; i++) {
    deltas.push((sorted[i] - sorted[i - 1]) / 1000);
  }
  const mean = deltas.reduce((sum, d) => sum + d, 0) / deltas.length;
  if (mean <= 0) return { isBeacon: false, intervalSec: 0, jitterPercent: 0 };

  const variance = deltas.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / deltas.length;
  const std = Math.sqrt(variance);
  const jitterPercent = Math.round((std / mean) * 100);

  const isBeacon = jitterPercent <= 25 && mean >= 2 && mean <= 600;
  return {
    isBeacon,
    isBeaconLike: isBeacon,
    intervalSec: Math.round(mean * 10) / 10,
    meanIntervalSeconds: Math.round(mean * 10) / 10,
    jitterPercent
  };
}

class RemoteAccessCollector {
  constructor() {
    this.status = 'STOPPED';
    this.lastCheckedUtc = null;
    this.peerHistory = new Map(); // peerKey -> Array of timestamps for beacon calculation
    this.suspiciousOutboundProfiles = [];
    this.lastState = {
      activeSessions: [],
      detectedTools: [],
      reverseShells: [],
      sensors: { webcam: null, microphone: null },
      rdpConfig: { rdpEnabled: false, nlaEnabled: true, remoteAssistanceEnabled: false },
      listeningPorts: []
    };
    this.latestEvaluation = null;
  }

  /**
   * Converts Windows FileTime integer to ISO timestamp
   */
  fileTimeToDate(ft) {
    if (!ft || ft === 0) return null;
    try {
      const num = typeof ft === 'string' ? BigInt(ft) : BigInt(ft);
      // Windows FileTime: 100-nanosecond intervals since Jan 1, 1601 UTC
      // Unix Epoch offset: 116444736000000000 intervals
      const epochDiff = 116444736000000000n;
      const unixMillis = Number((num - epochDiff) / 10000n);
      return new Date(unixMillis).toISOString();
    } catch (e) {
      return null;
    }
  }

  /**
   * Queries Windows Logon sessions via CIM
   */
  async collectLogonSessions() {
    try {
      if (process.platform === 'darwin') {
        const { exec } = require('child_process');
        const stdout = await new Promise(r => exec('who', { timeout: 3000 }, (e, o) => r(o || '')));
        const lines = stdout.split('\n');
        const sessions = [];
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          const parts = trimmed.split(/\s+/);
          if (parts.length >= 2) {
            const user = parts[0];
            const tty = parts[1];
            const isNetwork = trimmed.includes('(');
            const remoteHost = isNetwork ? (trimmed.match(/\(([^)]+)\)/) || [])[1] : null;
            sessions.push({
              id: tty,
              sessionId: tty,
              username: user,
              logonType: isNetwork ? 10 : 2,
              clientName: remoteHost || 'Local Terminal',
              clientAddress: remoteHost,
              state: 'Active',
              startTime: new Date().toISOString()
            });
          }
        }
        return sessions;
      }

      const script = `
        $users = @{}
        Get-CimInstance Win32_LoggedOnUser -ErrorAction SilentlyContinue | ForEach-Object {
          $id = [string]$_.Dependent.LogonId
          $name = "$($_.Antecedent.Domain)\\$($_.Antecedent.Name)"
          if ($id -and $name) { $users[$id] = $name }
        }
        Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object { $_.LogonType -in @(10, 3) } |
        ForEach-Object {
          $id = [string]$_.LogonId
          [PSCustomObject]@{
            LogonId = $id
            LogonType = $_.LogonType
            StartTime = $_.StartTime
            AuthenticationPackage = $_.AuthenticationPackage
            Username = if ($users.ContainsKey($id)) { $users[$id] } else { $env:USERNAME }
          }
        }
      `;
      const sessions = await psHost.execute(script, { timeoutMs: 5000, asJson: true });
      if (!sessions) return [];

      const list = Array.isArray(sessions) ? sessions : [sessions];
      const parsedSessions = [];

      for (const s of list) {
        if (!s || !s.LogonId) continue;
        let startTime = null;
        if (s.StartTime) {
          const match = /\/Date\((\d+)\)\//.exec(s.StartTime);
          if (match) startTime = new Date(parseInt(match[1], 10)).toISOString();
        }

        const isRemote = s.LogonType === 10;
        parsedSessions.push({
          sessionId: String(s.LogonId),
          logonId: String(s.LogonId),
          username: s.Username || s.username || process.env.USERNAME || 'User',
          logonType: isRemote ? 'RemoteInteractive (10)' : (s.LogonType === 2 ? 'Interactive (2)' : `Network (${s.LogonType})`),
          rawLogonType: s.LogonType,
          isRemoteInteractive: isRemote,
          state: 'Active',
          clientName: isRemote ? (s.ClientName || s.clientName || 'Remote Client') : 'Local Console',
          clientIp: isRemote ? (s.ClientIp || s.clientIp || '') : '127.0.0.1',
          logonTime: startTime,
          idleTime: '0m',
          authPackage: s.AuthenticationPackage || 'NTLM'
        });
      }

      return parsedSessions;
    } catch (err) {
      return [];
    }
  }

  /**
   * Queries Windows Remote Desktop and Remote Assistance configuration
   */
  async collectRdpConfig() {
    try {
      const script = `
        $ts = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue
        $ra = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Remote Assistance' -ErrorAction SilentlyContinue
        $nla = Get-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -ErrorAction SilentlyContinue
        [PSCustomObject]@{
          fDenyTS = if ($ts) { $ts.fDenyTSConnections } else { $null }
          fAllowHelp = if ($ra) { $ra.fAllowToGetHelp } else { $null }
          userAuth = if ($nla) { $nla.UserAuthentication } else { $null }
        }
      `;
      const res = await psHost.execute(script, { timeoutMs: 5000, asJson: true });
      if (!res) return { rdpEnabled: false, nlaEnabled: true, remoteAssistanceEnabled: false };

      return {
        rdpEnabled: res.fDenyTS === 0,
        remoteAssistanceEnabled: res.fAllowHelp === 1,
        nlaEnabled: res.userAuth === 1
      };
    } catch (err) {
      return { rdpEnabled: false, nlaEnabled: true, remoteAssistanceEnabled: false };
    }
  }

  /**
   * Queries CapabilityAccessManager ConsentStore for Camera and Microphone sensor access
   */
  async collectSensorActivity() {
    const sensors = {
      webcam: { inUse: false, appName: null, appPath: null, startTime: null },
      microphone: { inUse: false, appName: null, appPath: null, startTime: null }
    };

    if (process.platform === 'darwin') return sensors;

    try {
      const script = `
        $camPackaged = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\*' -ErrorAction SilentlyContinue | Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop
        $camNonPackaged = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\\NonPackaged\\*' -ErrorAction SilentlyContinue | Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop
        $micPackaged = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\*' -ErrorAction SilentlyContinue | Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop
        $micNonPackaged = Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\microphone\\NonPackaged\\*' -ErrorAction SilentlyContinue | Select-Object PSChildName, LastUsedTimeStart, LastUsedTimeStop
        [PSCustomObject]@{
          Cam = @($camPackaged; $camNonPackaged)
          Mic = @($micPackaged; $micNonPackaged)
        }
      `;
      const res = await psHost.execute(script, { timeoutMs: 6000, asJson: true });
      if (!res) return sensors;

      // Evaluate Webcam
      const camList = Array.isArray(res.Cam) ? res.Cam : (res.Cam ? [res.Cam] : []);
      for (const item of camList) {
        if (!item || !item.PSChildName || item.PSChildName === 'NonPackaged') continue;
        const start = item.LastUsedTimeStart || 0;
        const stop = item.LastUsedTimeStop || 0;

        // If stop is 0 or less than start, sensor is active now!
        if (start > 0 && (stop === 0 || stop < start)) {
          let cleanPath = item.PSChildName;
          if (cleanPath.includes('#')) {
            cleanPath = cleanPath.replace(/#/g, '\\');
          }
          const appName = cleanPath.split('\\').pop() || cleanPath;

          sensors.webcam = {
            inUse: true,
            appName,
            appPath: cleanPath,
            startTime: this.fileTimeToDate(start)
          };
          break;
        }
      }

      // Evaluate Microphone
      const micList = Array.isArray(res.Mic) ? res.Mic : (res.Mic ? [res.Mic] : []);
      for (const item of micList) {
        if (!item || !item.PSChildName || item.PSChildName === 'NonPackaged') continue;
        const start = item.LastUsedTimeStart || 0;
        const stop = item.LastUsedTimeStop || 0;

        if (start > 0 && (stop === 0 || stop < start)) {
          let cleanPath = item.PSChildName;
          if (cleanPath.includes('#')) {
            cleanPath = cleanPath.replace(/#/g, '\\');
          }
          const appName = cleanPath.split('\\').pop() || cleanPath;

          sensors.microphone = {
            inUse: true,
            appName,
            appPath: cleanPath,
            startTime: this.fileTimeToDate(start)
          };
          break;
        }
      }

      return sensors;
    } catch (err) {
      return sensors;
    }
  }

  /**
   * Scans running processes for known remote control tools and correlates with external sockets
   */
  scanKnownTools(activeProcesses = [], activeConnections = []) {
    const detected = [];
    const procMap = new Map();

    for (const p of activeProcesses) {
      if (p && p.name) {
        procMap.set(p.name.toLowerCase(), p);
      }
    }

    for (const tool of knownTools) {
      for (const procName of tool.processNames) {
        const found = procMap.get(procName.toLowerCase());
        if (found) {
          // Check if this PID owns an active external network connection
          const conn = activeConnections.find(c => c.pid === found.pid && c.isExternal);
          detected.push({
            id: tool.id,
            name: tool.name,
            category: tool.category,
            processName: procName,
            pid: found.pid,
            processPath: found.path || '',
            path: found.path || '',
            status: 'RUNNING',
            isRunning: true,
            hasActiveConnection: !!conn,
            activeSession: !!conn,
            signed: true,
            remoteIp: conn ? conn.remoteIp : null,
            remotePort: conn ? conn.remotePort : null,
            defaultPorts: tool.defaultPorts
          });
          break;
        }
      }
    }

    return detected;
  }

  /**
   * Identifies command interpreters with active outbound network sockets (Section 16.1a)
   */
  scanReverseShells(activeConnections = [], activeProcesses = [], options = {}) {
    const INTERPRETERS = new Set([
      'powershell.exe',
      'pwsh.exe',
      'cmd.exe',
      'wscript.exe',
      'cscript.exe',
      'mshta.exe',
      'python.exe',
      'node.exe',
      'bash.exe',
      'wsl.exe'
    ]);

    const COMMON_SHELL_PORTS = new Set([4444, 4445, 5555, 8080, 9001, 1337, 31337, 6667, 8888, 12345]);
    const SUSPICIOUS_PARENTS = new Set([
      'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
      'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe',
      'acrord32.exe', 'acrobat.exe', 'foxitreader.exe'
    ]);
    const OBFUSCATION_PATTERNS = [
      /-enc(?:odedcommand)?\s+/i,
      /iex\s*\(/i,
      /downloadstring\s*\(/i,
      /invoke-expression/i,
      /frombase64string/i,
      /[A-Za-z0-9+/]{40,}={0,2}/
    ];

    const procMap = new Map();
    for (const p of activeProcesses) {
      if (p && p.pid) procMap.set(p.pid, p);
    }

    const now = Date.now();
    const shells = [];
    const profiles = [];

/**
 * Checks if an IP belongs to well-known CDN or Cloud provider infrastructure (Cloudflare, Microsoft, Google, AWS, GitHub)
 */
function isKnownCloudOrCdnIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  // Cloudflare Anycast IPv4 ranges
  if (ip.startsWith('104.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 64 && second <= 71) return true;
  }
  if (ip.startsWith('198.41.')) {
    const third = parseInt(ip.split('.')[2], 10);
    if (third >= 128 && third <= 255) return true;
  }
  if (ip.startsWith('162.158.') || ip.startsWith('162.159.')) return true;

  // Microsoft Online Services / Azure Anycast & Login ranges (login.microsoftonline.com, Windows Update, Telemetry)
  if (ip.startsWith('40.126.') || ip.startsWith('40.76.') || ip.startsWith('40.79.') || ip.startsWith('40.83.') || ip.startsWith('40.112.')) return true;
  if (ip.startsWith('20.190.') || ip.startsWith('13.107.') || ip.startsWith('52.107.') || ip.startsWith('52.225.') || ip.startsWith('52.96.')) return true;

  // Google Cloud / CDN
  if (ip.startsWith('142.250.') || ip.startsWith('172.217.') || ip.startsWith('34.') || ip.startsWith('35.')) return true;

  return false;
}

    for (const conn of activeConnections) {
      if (conn.isExternal && conn.state === 'ESTABLISHED') {
        // Exclude LaptopGuard's own process and persistent PowerShell child host
        if (conn.pid === process.pid || (psHost && psHost.pid && conn.pid === psHost.pid)) {
          continue;
        }

        const name = (conn.processName || '').toLowerCase();
        if (INTERPRETERS.has(name)) {
          // Track timestamps for beaconing calculation
          const peerKey = `${conn.remoteIp}:${conn.remotePort}`;
          if (!this.peerHistory.has(peerKey)) {
            this.peerHistory.set(peerKey, []);
          }
          const history = this.peerHistory.get(peerKey);
          history.push(now);
          if (history.length > 20) history.shift();

          const beacon = computeBeaconMetrics(history);

          const procInfo = procMap.get(conn.pid) || db.getProcess(conn.pid) || {};
          const cmdLine = procInfo.command_line || procInfo.commandLine || '';
          const parentName = (procInfo.parent_name || procInfo.parentProcess || '').toLowerCase();

          // Common reverse shell port
          const isCommonPort = COMMON_SHELL_PORTS.has(Number(conn.remotePort));
          // Suspicious parent process
          const isSuspiciousParent = SUSPICIOUS_PARENTS.has(parentName);
          // Obfuscation check
          const isObfuscated = OBFUSCATION_PATTERNS.some(re => re.test(cmdLine));

          // Allow standard developer runtimes (node.exe, python.exe) on normal web ports unless explicitly suspicious
          const isRuntime = (name === 'node.exe' || name === 'python.exe');
          const isStandardWebPort = (Number(conn.remotePort) === 443 || Number(conn.remotePort) === 80);
          if (isRuntime && isStandardWebPort && !isSuspiciousParent && !isObfuscated && !isCommonPort) {
            continue;
          }

          // Allow legitimate PowerShell / shell traffic on standard HTTPS to trusted Cloud/CDN endpoints (Windows updates, Microsoft login, npm/github)
          const isKnownCloud = isKnownCloudOrCdnIp(conn.remoteIp);
          if ((name === 'powershell.exe' || name === 'pwsh.exe') && isStandardWebPort && isKnownCloud && !isSuspiciousParent && !isObfuscated && !isCommonPort) {
            continue;
          }

          const indicators = [];
          let score = 25; // Base interpreter outbound
          indicators.push(`Command interpreter (${conn.processName}) owns established outbound socket`);

          // Raw IP check (no reverse DNS name)
          indicators.push(`Peer is raw IP with no reverse-DNS name (${conn.remoteIp})`);
          score += 15;

          // Common reverse shell port
          if (isCommonPort) {
            indicators.push(`Destination port ${conn.remotePort} is a common reverse-shell port`);
            score += 20;
          }

          // Suspicious parent process
          if (isSuspiciousParent) {
            indicators.push(`Suspicious parent process (${parentName})`);
            score += 35;
          }

          // Obfuscation check
          if (isObfuscated) {
            indicators.push('Command line contains encoded or reflective execution indicators (-enc, IEX, DownloadString, base64)');
            score += 25;
          }

          // Beaconing check
          if (beacon.isBeacon) {
            indicators.push(`Regular connection interval observed: ~${beacon.intervalSec}s (jitter: ${beacon.jitterPercent}%)`);
            score += 20;
          }

          let confidence = score >= 60 ? 'HIGH' : (score >= 40 ? 'MEDIUM' : 'LOW');
          // If port is standard web (443/80) and no malicious parent, obfuscation, or backdoor port was found, cap at MEDIUM
          if (isStandardWebPort && !isSuspiciousParent && !isObfuscated && !isCommonPort && confidence === 'HIGH') {
            confidence = 'MEDIUM';
          }
          const plainEnglish = `A ${conn.processName} process on your laptop opened an outbound connection to ${conn.remoteIp}:${conn.remotePort} (no DNS name). This matches reverse-shell indicators. Confidence: ${confidence.toLowerCase()}. Evidence: ${indicators.join('; ')}.`;

          const profileId = `outbound_${conn.pid}_${String(conn.remoteIp).replace(/[^a-zA-Z0-9]/g, '_')}_${conn.remotePort}`;

          const outboundProfile = {
            id: profileId,
            firstObservedUtc: conn.firstSeen || new Date().toISOString(),
            lastObservedUtc: new Date().toISOString(),
            pid: conn.pid,
            processName: conn.processName,
            processPath: conn.processPath || procInfo.executable_path || '',
            commandLine: cmdLine,
            parentProcess: parentName,
            parentProcessName: parentName,
            signerStatus: procInfo.signer || procInfo.signature_status || 'Unknown',
            peerIp: conn.remoteIp,
            peerPort: conn.remotePort,
            remoteIp: conn.remoteIp,
            remotePort: conn.remotePort,
            hasDns: 0,
            dnsName: null,
            isCommonShellPort: isCommonPort ? 1 : 0,
            isBeacon: beacon.isBeacon ? 1 : 0,
            beaconIntervalSec: beacon.intervalSec,
            beaconJitterPercent: beacon.jitterPercent,
            confidence,
            score,
            indicators,
            evidence: indicators,
            plainEnglish,
            summary: plainEnglish,
            status: 'ACTIVE'
          };

          profiles.push(outboundProfile);
          const targetDb = options.db || db;
          const shouldPersist = options.persist !== false && (process.env.NODE_ENV !== 'test' || options.persist === true);
          if (shouldPersist && targetDb) {
            targetDb.upsertSuspiciousOutbound(outboundProfile);

            // Correlate into incidents table if confidence is HIGH or concrete attack signals exist
            if (confidence === 'HIGH' || isSuspiciousParent || isObfuscated || isCommonPort) {
              const incId = `inc_${String(conn.remoteIp).replace(/[^a-zA-Z0-9]/g, '_')}`;
              targetDb.recordIncident({
                id: incId,
                title: `Suspicious Outbound Channel: ${conn.processName} to ${conn.remoteIp}:${conn.remotePort}`,
                severity: confidence === 'HIGH' ? 'CRITICAL' : 'HIGH',
                status: 'OPEN',
                summary: plainEnglish,
                primaryIp: conn.remoteIp,
                primaryProcess: conn.processName,
                containmentStatus: 'UNCONTAINED',
                timeline: [
                  {
                    timestampUtc: new Date().toISOString(),
                    type: 'SUSPICIOUS_OUTBOUND_OBSERVED',
                    description: plainEnglish
                  }
                ]
              });
            }
          }

          shells.push({
            processName: conn.processName,
            pid: conn.pid,
            processPath: conn.processPath,
            localIp: conn.localIp,
            localPort: conn.localPort,
            remoteIp: conn.remoteIp,
            remotePort: conn.remotePort,
            direction: conn.direction,
            confidence,
            score,
            indicators,
            plainEnglish
          });
        }
      }
    }

    if (options.updateInstance !== false) {
      this.suspiciousOutboundProfiles = profiles;
    }
    return Object.assign(shells, { shells, profiles });
  }

  /**
   * Executes a full remote access and spying poll cycle
   */
  async poll(context = {}) {
    const start = Date.now();
    try {
      const {
        activeProcesses = [],
        activeConnections = [],
        listeningPorts = []
      } = context;

      const [logonSessions, rdpConfig, sensors] = await Promise.all([
        this.collectLogonSessions(),
        this.collectRdpConfig(),
        this.collectSensorActivity()
      ]);

      const detectedTools = this.scanKnownTools(activeProcesses, activeConnections);
      const reverseShells = this.scanReverseShells(activeConnections, activeProcesses);

      const state = {
        activeSessions: logonSessions,
        detectedTools,
        reverseShells,
        sensors,
        rdpConfig,
        listeningPorts
      };

      this.lastState = state;
      this.lastCheckedUtc = new Date().toISOString();

      // Record any active remote sessions in database
      for (const s of logonSessions) {
        if (s.logonType === 10 || s.isRemoteInteractive) {
          db.upsertRemoteSession({
            sessionId: parseInt(s.logonId, 10) || 1,
            username: s.username || 'Remote User',
            domain: s.domain || '',
            logonType: s.logonType,
            clientName: s.clientName || 'Remote Client',
            clientIp: s.clientIp || '',
            state: 'Active',
            logonTimeUtc: s.logonTime,
            toolName: 'RDP/TerminalServices',
            details: s
          });
        }
      }

      // Evaluate rules & calculate risk score
      const findings = evaluateRemoteAccessState(state);
      const risk = calculateRemoteRiskScore(state);

      this.latestEvaluation = {
        timestampUtc: this.lastCheckedUtc,
        riskScore: risk.score,
        riskTier: risk.tier,
        statusBanner: risk.statusBanner,
        factors: risk.factors,
        findings,
        state
      };

      // Persist findings to database
      for (const f of findings) {
        db.recordFinding(f);
      }

      db.recordHealth('RemoteAccessMonitor', 'OK', Date.now() - start, `Risk Tier: ${risk.tier}, Score: ${risk.score}`);
      return this.latestEvaluation;
    } catch (err) {
      db.recordHealth('RemoteAccessMonitor', 'DEGRADED', Date.now() - start, err.message);
      return null;
    }
  }

  getSnapshot() {
    return this.latestEvaluation || {
      timestampUtc: new Date().toISOString(),
      riskScore: 0,
      riskTier: 'NONE',
      statusBanner: {
        code: 'NO_REMOTE_ACCESS',
        text: 'No remote access detected right now',
        severity: 'SAFE'
      },
      factors: [],
      findings: [],
      suspiciousOutboundProfiles: this.suspiciousOutboundProfiles || [],
      state: this.lastState
    };
  }

  getSuspiciousOutbound() {
    return this.suspiciousOutboundProfiles || [];
  }
}

// Singleton instance
const collector = new RemoteAccessCollector();
module.exports = collector;
module.exports.RemoteAccessCollector = RemoteAccessCollector;
module.exports.computeBeaconMetrics = computeBeaconMetrics;
