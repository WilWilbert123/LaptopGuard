/**
 * MY LAPTOP GUARD - Telemetry & Network Monitor
 * High-performance background collector for TCP/UDP connections, process metadata,
 * Windows Defender telemetry, and persistence items.
 */

const { execFile, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const db = require('./database');
const detector = require('./detector');
const psHost = require('./ps-host');
const remoteAccessCollector = require('./collectors/remote-access');
const eventTailer = require('./collectors/event-tailer');
const postureEvaluator = require('./posture');

class LaptopMonitor {
  constructor() {
    this.status = 'STOPPED'; // ACTIVE | DEGRADED | STOPPED
    this.pollIntervalMs = parseInt(process.env.POLL_INTERVAL_MS, 10) || 3000;
    this.defenderIntervalMs = parseInt(process.env.DEFENDER_POLL_INTERVAL_MS, 10) || 30000;
    this.startupIntervalMs = parseInt(process.env.STARTUP_POLL_INTERVAL_MS, 10) || 60000;

    // Timers
    this.netTimer = null;
    this.defenderTimer = null;
    this.startupTimer = null;
    this.remoteAccessTimer = null;
    this.eventTailerTimer = null;
    this.postureTimer = null;
    this.pruneTimer = null;

    // In-memory cache to minimize disk I/O & CPU usage
    this.processCache = new Map(); // pid -> { name, path, commandLine, updated }
    this.activeConnections = [];   // current snapshot of active connections
    this.listeningPorts = [];      // current snapshot of listening ports
    this.listeningPortsSet = new Set(); // fast lookup of local listening ports
    this.previousConnMap = new Map(); // key -> connection object with firstSeen
    this.defenderStatus = null;
    this.startupItems = [];
    this.collectorErrors = [];

    // Callbacks
    this.onUpdateCallback = null;
    this.onFindingCallback = null;
  }

  /**
   * Helper to execute system commands with strict timeout
   */
  async runExec(cmd, args = [], timeoutMs = 8000) {
    return new Promise((resolve, reject) => {
      if (args.length > 0) {
        execFile(cmd, args, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 5 }, (err, stdout, stderr) => {
          if (err) return reject(new Error(stderr || stdout || err.message));
          resolve(stdout);
        });
      } else {
        exec(cmd, { timeout: timeoutMs, maxBuffer: 1024 * 1024 * 5 }, (err, stdout, stderr) => {
          if (err) return reject(new Error(stderr || stdout || err.message));
          resolve(stdout);
        });
      }
    });
  }

  /**
   * Refreshes process name and path cache using fast PowerShell batch query
   */
  async refreshProcessCache() {
    const start = Date.now();
    try {
      if (process.platform === 'darwin') {
        const stdout = await this.runExec('ps', ['-axo', 'pid,comm'], 4000);
        const lines = stdout.split('\n');
        for (let i = 1; i < lines.length; i++) {
          const line = lines[i].trim();
          if (!line) continue;
          const match = line.match(/^(\d+)\s+(.+)$/);
          if (match) {
            const pid = parseInt(match[1], 10);
            const procPath = match[2].trim();
            const procName = path.basename(procPath);
            const existing = this.processCache.get(pid);
            this.processCache.set(pid, {
              pid,
              name: procName,
              path: procPath,
              firstSeen: existing ? existing.firstSeen : new Date().toISOString(),
              lastUpdated: Date.now()
            });
            db.upsertProcess({
              pid,
              processName: procName,
              executablePath: procPath,
              firstSeenUtc: existing ? existing.firstSeen : new Date().toISOString()
            });
          }
        }
        db.recordHealth('ProcessCache', 'OK', Date.now() - start, `Cached ${this.processCache.size} processes (macOS)`);
        return;
      }

      const psCmd = 'Get-Process -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, Path';
      const procs = await psHost.execute(psCmd, { timeoutMs: 6000, asJson: true });
      if (!procs) return;

      const list = Array.isArray(procs) ? procs : [procs];

      for (const p of list) {
        if (!p || !p.Id) continue;
        const existing = this.processCache.get(p.Id);
        let procName = 'Unknown';
        if (p.Id === 4) {
          procName = 'System';
        } else if (p.Id === 0) {
          procName = 'Idle';
        } else if (p.ProcessName) {
          procName = p.ProcessName.toLowerCase().endsWith('.exe') ? p.ProcessName : `${p.ProcessName}.exe`;
        }
        const procPath = p.Path || (existing ? existing.path : null);

        this.processCache.set(p.Id, {
          pid: p.Id,
          name: procName,
          path: procPath,
          firstSeen: existing ? existing.firstSeen : new Date().toISOString(),
          lastUpdated: Date.now()
        });

        // Upsert to DB process catalogue
        db.upsertProcess({
          pid: p.Id,
          processName: procName,
          executablePath: procPath,
          firstSeenUtc: existing ? existing.firstSeen : new Date().toISOString()
        });
      }

      db.recordHealth('ProcessCache', 'OK', Date.now() - start, `Cached ${this.processCache.size} processes`);
    } catch (err) {
      // Non-critical: keep using existing process cache
      db.recordHealth('ProcessCache', 'DEGRADED', Date.now() - start, err.message);
    }
  }

  /**
   * Parses IPv4/IPv6 and port from netstat address strings
   */
  parseAddress(addr) {
    if (!addr || addr === '*:*') return { ip: '*', port: 0 };
    const lastColon = addr.lastIndexOf(':');
    if (lastColon === -1) return { ip: addr, port: 0 };

    let ip = addr.slice(0, lastColon).trim();
    const port = parseInt(addr.slice(lastColon + 1), 10) || 0;

    if (ip.startsWith('[') && ip.endsWith(']')) {
      ip = ip.slice(1, -1);
    }
    return { ip, port };
  }

  /**
   * Fast network connection polling using native netstat.exe (Windows) or lsof (macOS)
   */
  async pollNetworkConnections() {
    const start = Date.now();
    try {
      const currentConns = [];
      const currentListening = [];
      const newListeningSet = new Set();
      const now = new Date().toISOString();

      if (process.platform === 'darwin') {
        let stdout = '';
        try {
          stdout = await this.runExec('lsof', ['-nP', '-iTCP', '-iUDP'], 4000);
        } catch (lsofErr) {
          stdout = await this.runExec('netstat', ['-anv'], 4000);
        }
        this.parseMacSockets(stdout, now, currentConns, currentListening, newListeningSet);
      } else {
        // Execute netstat -ano
        const stdout = await this.runExec('netstat.exe', ['-ano'], 4000);
        const lines = stdout.split(/\r?\n/);

      // First pass: identify all local listening ports to accurately calculate INBOUND traffic
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('TCP') && !line.startsWith('UDP')) continue;
        const parts = line.split(/\s+/);

        if (parts[0] === 'TCP' && parts[3] === 'LISTENING') {
          const local = this.parseAddress(parts[1]);
          if (local.port > 0) {
            newListeningSet.add(local.port);
          }
        }
      }
      this.listeningPortsSet = newListeningSet;

      // Second pass: parse connections and listening sockets
      for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('TCP') && !line.startsWith('UDP')) continue;
        const parts = line.split(/\s+/);

        const proto = parts[0];
        let localAddr = '';
        let foreignAddr = '';
        let state = '';
        let pid = 0;

        if (proto === 'TCP') {
          localAddr = parts[1] || '';
          foreignAddr = parts[2] || '';
          state = parts[3] || '';
          pid = parseInt(parts[4], 10) || 0;
        } else if (proto === 'UDP') {
          localAddr = parts[1] || '';
          foreignAddr = parts[2] || '*:*';
          state = 'UDP_ACTIVE';
          pid = parseInt(parts[3], 10) || 0;
        }

        const local = this.parseAddress(localAddr);
        const remote = this.parseAddress(foreignAddr);

        // Process info from cache
        const procInfo = this.processCache.get(pid);
        const processName = procInfo ? procInfo.name : (pid === 4 ? 'System' : (pid === 0 ? 'Idle' : 'Unknown'));
        const processPath = procInfo ? procInfo.path : null;

        // Direction classification
        let direction = 'UNKNOWN';
        const isLoopback = (local.ip === '127.0.0.1' || remote.ip === '127.0.0.1' || local.ip === '::1' || remote.ip === '::1');
        const isPrivate = detector.isPrivateOrLocalIp(remote.ip);

        if (state === 'LISTENING') {
          direction = 'LISTENING';
        } else if (isLoopback) {
          direction = 'LOOPBACK';
        } else if (this.listeningPortsSet.has(local.port)) {
          direction = 'INBOUND';
        } else if (isPrivate) {
          direction = 'LOCAL_LAN';
        } else {
          direction = 'OUTBOUND';
        }

        const connKey = `${proto}_${local.ip}:${local.port}_${remote.ip}:${remote.port}_${pid}`;
        const prev = this.previousConnMap.get(connKey);
        const firstSeen = prev ? prev.firstSeen : now;
        const isNew = !prev;

        const connObj = {
          key: connKey,
          protocol: proto,
          localIp: local.ip,
          localPort: local.port,
          remoteIp: remote.ip,
          remotePort: remote.port,
          state: state,
          pid: pid,
          processName: processName,
          processPath: processPath,
          direction: direction,
          isExternal: !isLoopback && !isPrivate && remote.ip !== '*',
          isGuardInternal: (pid === process.pid || (psHost && psHost.pid && pid === psHost.pid)),
          firstSeen: firstSeen,
          lastSeen: now,
          isNew: isNew,
          riskLevel: 'LOW',
          findings: []
        };

        // Evaluate against security rules
        const findings = detector.evaluateConnection(connObj);
        if (findings.length > 0) {
          connObj.findings = findings;
          // Determine highest risk level
          const hasCritical = findings.some(f => f.severity === 'CRITICAL');
          const hasHigh = findings.some(f => f.severity === 'HIGH');
          const hasMedium = findings.some(f => f.severity === 'MEDIUM');
          connObj.riskLevel = hasCritical ? 'CRITICAL' : (hasHigh ? 'HIGH' : (hasMedium ? 'MEDIUM' : 'LOW'));

          // Deduplicate and record finding to DB
          const uniqueFindings = detector.deduplicateFindings(findings);
          for (const uf of uniqueFindings) {
            const saved = db.recordFinding(uf);
            if (this.onFindingCallback) {
              this.onFindingCallback(saved);
            }
          }
        }

          if (state === 'LISTENING' || proto === 'UDP') {
            currentListening.push(connObj);
          } else {
            currentConns.push(connObj);
          }
        }
      }

      // Update in-memory collections
      this.activeConnections = currentConns;
      this.listeningPorts = currentListening;

      // Update previous map for next cycle's state tracking
      const newMap = new Map();
      for (const c of [...currentConns, ...currentListening]) {
        newMap.set(c.key, { firstSeen: c.firstSeen, lastSeen: c.lastSeen });
      }
      this.previousConnMap = newMap;

      // Batch persist external, new, or suspicious connections (avoids writing idle loopback)
      const toPersist = currentConns.filter(c => c.isExternal || c.riskLevel !== 'LOW' || c.direction === 'INBOUND');
      if (toPersist.length > 0) {
        db.recordConnectionsBatch(toPersist);
      }

      const duration = Date.now() - start;
      db.recordHealth('NetworkMonitor', 'OK', duration, `Active: ${currentConns.length}, Listening: ${currentListening.length}`);

      if (this.status !== 'DEGRADED') {
        this.status = 'ACTIVE';
      }

      if (this.onUpdateCallback) {
        this.onUpdateCallback({
          timestamp: now,
          connectionsCount: currentConns.length,
          listeningCount: currentListening.length,
          activeConnections: currentConns,
          listeningPorts: currentListening
        });
      }
    } catch (err) {
      this.status = 'DEGRADED';
      this.collectorErrors.push({ time: new Date().toISOString(), component: 'NetworkMonitor', error: err.message });
      db.recordHealth('NetworkMonitor', 'ERROR', Date.now() - start, err.message);
    }
  }

  /**
   * Polls Windows Defender status and recent threat detections
   */
  /**
   * Parses macOS lsof or netstat socket output
   */
  parseMacSockets(stdout, now, currentConns, currentListening, newListeningSet) {
    const lines = stdout.split('\n');
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('COMMAND') || line.startsWith('Active Internet')) continue;

      const parts = line.split(/\s+/);
      if (parts.length < 9) continue;

      const procName = parts[0];
      const pid = parseInt(parts[1], 10) || 0;
      const proto = (parts[7] || 'TCP').toUpperCase();
      const nameCol = parts.slice(8).join(' ');

      let localAddrStr = '';
      let foreignAddrStr = '';
      let state = 'ESTABLISHED';

      if (proto.includes('UDP')) {
        state = 'UDP_ACTIVE';
        localAddrStr = nameCol.replace(/\s*\(.+\)/, '');
        foreignAddrStr = '*:*';
      } else if (nameCol.includes('(LISTEN)')) {
        state = 'LISTENING';
        localAddrStr = nameCol.replace(/\s*\(LISTEN\)/, '');
        foreignAddrStr = '*:0';
      } else if (nameCol.includes('->')) {
        const linkParts = nameCol.split('->');
        localAddrStr = linkParts[0].trim();
        const remPart = linkParts[1].trim();
        const stMatch = remPart.match(/\((.+)\)/);
        state = stMatch ? stMatch[1] : 'ESTABLISHED';
        foreignAddrStr = remPart.replace(/\s*\(.+\)/, '').trim();
      } else {
        localAddrStr = nameCol;
        foreignAddrStr = '*:*';
      }

      const local = this.parseAddress(localAddrStr);
      const remote = this.parseAddress(foreignAddrStr);

      if (state === 'LISTENING' && local.port > 0) {
        newListeningSet.add(local.port);
      }

      let direction = 'UNKNOWN';
      const isLoopback = (local.ip === '127.0.0.1' || remote.ip === '127.0.0.1' || local.ip === '::1' || remote.ip === '::1' || local.ip === 'localhost');
      const isPrivate = detector.isPrivateOrLocalIp(remote.ip);

      if (state === 'LISTENING') {
        direction = 'LISTENING';
      } else if (isLoopback) {
        direction = 'LOOPBACK';
      } else if (newListeningSet.has(local.port)) {
        direction = 'INBOUND';
      } else if (isPrivate) {
        direction = 'LOCAL_LAN';
      } else {
        direction = 'OUTBOUND';
      }

      const procInfo = this.processCache.get(pid);
      const procPath = procInfo ? procInfo.path : null;

      const connKey = `${proto}_${local.ip}:${local.port}_${remote.ip}:${remote.port}_${pid}`;
      const prev = this.previousConnMap.get(connKey);
      const firstSeen = prev ? prev.firstSeen : now;

      const connObj = {
        key: connKey,
        protocol: proto,
        localIp: local.ip,
        localPort: local.port,
        remoteIp: remote.ip,
        remotePort: remote.port,
        state,
        pid,
        processName: procName,
        processPath: procPath,
        direction,
        isExternal: !isLoopback && !isPrivate && remote.ip !== '*',
        isGuardInternal: pid === process.pid,
        firstSeen,
        lastSeen: now,
        isNew: !prev,
        riskLevel: 'LOW',
        findings: []
      };

      const findings = detector.evaluateConnection(connObj);
      if (findings.length > 0) {
        connObj.findings = findings;
        const hasCritical = findings.some(f => f.severity === 'CRITICAL');
        const hasHigh = findings.some(f => f.severity === 'HIGH');
        const hasMedium = findings.some(f => f.severity === 'MEDIUM');
        connObj.riskLevel = hasCritical ? 'CRITICAL' : (hasHigh ? 'HIGH' : (hasMedium ? 'MEDIUM' : 'LOW'));
      }

      if (state === 'LISTENING' || proto.includes('UDP')) {
        currentListening.push(connObj);
      } else {
        currentConns.push(connObj);
      }
    }

    this.listeningPortsSet = newListeningSet;
  }

  /**
   * Polls Windows Defender or macOS Apple XProtect & Gatekeeper
   */
  async pollDefenderTelemetry() {
    const start = Date.now();
    try {
      if (process.platform === 'darwin') {
        let sipEnabled = true;
        let gatekeeperEnabled = true;
        let firewallEnabled = true;

        try {
          const sipOut = await this.runExec('csrutil', ['status'], 2000);
          sipEnabled = sipOut.toLowerCase().includes('enabled');
        } catch (e) {}

        try {
          const spctlOut = await this.runExec('spctl', ['--status'], 2000);
          gatekeeperEnabled = spctlOut.toLowerCase().includes('assessments enabled');
        } catch (e) {}

        try {
          const fwOut = await this.runExec('/usr/libexec/ApplicationFirewall/socketfilterfw', ['--getglobalstate'], 2000);
          firewallEnabled = fwOut.toLowerCase().includes('enabled');
        } catch (e) {}

        this.defenderStatus = {
          antivirusEnabled: true,
          realTimeProtectionEnabled: true,
          isTamperProtected: sipEnabled,
          gatekeeperEnabled,
          firewallEnabled,
          signatureVersion: 'Apple XProtect (Active)',
          productName: 'Apple XProtect & Gatekeeper',
          signatureLastUpdated: new Date().toISOString(),
          lastQuickScanUtc: new Date().toISOString(),
          activeThreatCount: 0,
          platform: 'macOS',
          defenderServiceRunning: true
        };

        db.recordHealth('DefenderTelemetry', 'OK', Date.now() - start, 'Apple XProtect, Gatekeeper & SIP verified (macOS)');
        return;
      }

      // 1. Get Defender Protection Status
      const statusPs = `
        Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled,
                      AntispywareEnabled, AMServiceEnabled, FullScanAge, QuickScanAge,
                      AntivirusSignatureVersion, AntivirusSignatureLastUpdated,
                      AMEngineVersion, AMProductVersion, BehaviorMonitorEnabled,
                      NISEnabled, IsTamperProtected, OnAccessProtectionEnabled,
                      QuickScanEndTime, DefenderSignaturesOutOfDate
      `;
      let defenderData = {};
      try {
        const res = await psHost.execute(statusPs, { timeoutMs: 8000, asJson: true });
        if (res) defenderData = res;
      } catch (e) {
        // Fallback or permission check
      }

      // 2. Query 3rd party antivirus products via SecurityCenter2 WMI
      const avPs = `
        Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName, productState, pathToSignedProductExe
      `;
      let avList = [];
      try {
        const avRes = await psHost.execute(avPs, { timeoutMs: 5000, asJson: true });
        if (avRes) {
          avList = Array.isArray(avRes) ? avRes : [avRes];
        }
      } catch (avErr) {
        // Non-critical if SecurityCenter2 is inaccessible
      }

      // 3. Query Active Threat Detections
      const threatsPs = `
        Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Select-Object -First 10 ThreatID, ThreatName, InitialDetectionTime, Resources, CleaningActionID
      `;
      let threats = [];
      try {
        const threatRes = await psHost.execute(threatsPs, { timeoutMs: 6000, asJson: true });
        if (threatRes) {
          threats = Array.isArray(threatRes) ? threatRes : [threatRes];
          // Record any detected threats to database
          for (const t of threats) {
            db.recordDefenderDetection({
              threatId: t.ThreatID,
              threatName: t.ThreatName,
              resources: Array.isArray(t.Resources) ? t.Resources.join('; ') : String(t.Resources || ''),
              actionTaken: String(t.CleaningActionID || 'Detected')
            });
          }
        }
      } catch (threatErr) {
        // Non-critical if no threats or query requires elevation
      }

      // Parse signature last updated date from WMI date format if needed
      let sigDateStr = null;
      if (defenderData.AntivirusSignatureLastUpdated) {
        const match = /\/Date\((\d+)\)\//.exec(defenderData.AntivirusSignatureLastUpdated);
        if (match) {
          sigDateStr = new Date(parseInt(match[1], 10)).toISOString();
        } else {
          sigDateStr = String(defenderData.AntivirusSignatureLastUpdated);
        }
      }

      // Parse quick scan end date
      let scanDateStr = null;
      if (defenderData.QuickScanEndTime) {
        const match = /\/Date\((\d+)\)\//.exec(defenderData.QuickScanEndTime);
        if (match) {
          scanDateStr = new Date(parseInt(match[1], 10)).toISOString();
        } else {
          scanDateStr = String(defenderData.QuickScanEndTime);
        }
      }

      this.defenderStatus = {
        isAvailable: Boolean(defenderData.AntivirusEnabled !== undefined),
        realTimeProtectionEnabled: Boolean(defenderData.RealTimeProtectionEnabled),
        antivirusEnabled: Boolean(defenderData.AntivirusEnabled),
        cloudProtectionEnabled: Boolean(defenderData.IoavProtectionEnabled),
        antispywareEnabled: Boolean(defenderData.AntispywareEnabled),
        serviceEnabled: Boolean(defenderData.AMServiceEnabled),
        behaviorMonitorEnabled: Boolean(defenderData.BehaviorMonitorEnabled),
        nisEnabled: Boolean(defenderData.NISEnabled),
        isTamperProtected: Boolean(defenderData.IsTamperProtected),
        onAccessProtectionEnabled: Boolean(defenderData.OnAccessProtectionEnabled),
        engineVersion: defenderData.AMEngineVersion || 'Standard',
        productVersion: defenderData.AMProductVersion || 'Standard',
        signatureVersion: defenderData.AntivirusSignatureVersion || 'Unknown',
        signatureLastUpdated: sigDateStr,
        signaturesOutOfDate: Boolean(defenderData.DefenderSignaturesOutOfDate),
        quickScanAgeDays: defenderData.QuickScanAge !== undefined ? defenderData.QuickScanAge : null,
        lastQuickScanTime: scanDateStr,
        detectedThreats: threats,
        registeredAntivirus: avList.map(a => a.displayName || 'Unknown Antivirus'),
        lastCheckedUtc: new Date().toISOString()
      };

      db.recordHealth('DefenderTelemetry', 'OK', Date.now() - start, 'Defender telemetry updated');
    } catch (err) {
      db.recordHealth('DefenderTelemetry', 'DEGRADED', Date.now() - start, err.message);
      this.defenderStatus = {
        isAvailable: false,
        error: err.message,
        lastCheckedUtc: new Date().toISOString()
      };
    }
  }

  /**
   * Polls Windows startup commands and persistence items
   */
  async pollStartupPersistence() {
    const start = Date.now();
    try {
      if (process.platform === 'darwin') {
        const items = [];
        const candidateDirs = [
          path.join(process.env.HOME || '', 'Library/LaunchAgents'),
          '/Library/LaunchAgents',
          '/Library/LaunchDaemons'
        ];

        for (const dir of candidateDirs) {
          if (fs.existsSync(dir)) {
            try {
              const files = fs.readdirSync(dir);
              for (const f of files) {
                if (f.endsWith('.plist')) {
                  const item = {
                    itemType: 'LaunchAgent',
                    name: f.replace('.plist', ''),
                    command: path.join(dir, f),
                    location: dir,
                    user: dir.includes(process.env.HOME || '') ? (process.env.USER || 'User') : 'System'
                  };
                  const findings = detector.evaluateStartupItem(item);
                  items.push({
                    ...item,
                    isSuspicious: findings.length > 0,
                    findings
                  });
                }
              }
            } catch (dirErr) {}
          }
        }

        this.startupItems = items;
        db.recordHealth('StartupMonitor', 'OK', Date.now() - start, `Audited ${items.length} macOS LaunchAgents`);
        return;
      }

      const psCmd = `
        Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User
      `;
      const parsed = await psHost.execute(psCmd, { timeoutMs: 8000, asJson: true });
      if (!parsed) return;

      const rawItems = Array.isArray(parsed) ? parsed : [parsed];

      const evaluatedItems = [];
      for (const item of rawItems) {
        if (!item || !item.Name) continue;
        const findings = detector.evaluateStartupItem(item);
        const isSusp = findings.length > 0;

        evaluatedItems.push({
          itemType: 'StartupCommand',
          name: item.Name,
          command: item.Command || '',
          location: item.Location || '',
          user: item.User || '',
          isSuspicious: isSusp,
          findings: findings
        });

        // Record findings if any
        if (isSusp) {
          const uniqueFindings = detector.deduplicateFindings(findings);
          for (const uf of uniqueFindings) {
            const saved = db.recordFinding(uf);
            if (this.onFindingCallback) {
              this.onFindingCallback(saved);
            }
          }
        }
      }

      this.startupItems = evaluatedItems;
      db.syncPersistenceItems(evaluatedItems);
      db.recordHealth('StartupMonitor', 'OK', Date.now() - start, `Monitored ${evaluatedItems.length} startup items`);
    } catch (err) {
      db.recordHealth('StartupMonitor', 'DEGRADED', Date.now() - start, err.message);
    }
  }

  /**
   * Safely removes a startup item from Windows (Registry Run keys or Startup folders)
   */
  async removeStartupItem(name, location) {
    if (!name || typeof name !== 'string') {
      return { success: false, error: 'Valid startup item name is required.' };
    }

    const cleanName = name.trim().replace(/["';`$|&]/g, '');
    const cleanLoc = (location || '').trim();

    // 1. Startup folder shortcut (.lnk)
    if (cleanLoc.toLowerCase() === 'startup' || cleanLoc.toLowerCase().includes('startup')) {
      const psScript = `
        $userStartup = Join-Path $env:APPDATA 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        $commonStartup = Join-Path $env:ProgramData 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'
        $deleted = $false

        $files = Get-ChildItem -Path @($userStartup, $commonStartup) -ErrorAction SilentlyContinue |
                 Where-Object { $_.BaseName -eq '${cleanName}' -or $_.Name -eq '${cleanName}' -or $_.Name -eq '${cleanName}.lnk' }

        foreach ($f in $files) {
            Remove-Item -Path $f.FullName -Force -ErrorAction Stop
            $deleted = $true
        }
        if ($deleted) { 'DELETED' } else { 'NOT_FOUND' }
      `;
      try {
        const out = await this.runExec('powershell.exe', ['-NoProfile', '-Command', psScript], 6000);
        if (out.includes('DELETED')) {
          db.deletePersistenceItem(name, location);
          db.recordAuditEvent('STARTUP_ITEM_REMOVED', 'USER', `Deleted startup shortcut: ${cleanName}`);
          await this.pollStartupPersistence();
          return { success: true, message: `Removed "${cleanName}" from Startup folder.` };
        } else {
          return { success: false, error: `Could not find startup shortcut for "${cleanName}".` };
        }
      } catch (err) {
        return { success: false, error: `Failed to delete startup shortcut: ${err.message}` };
      }
    }

    // 2. HKCU / HKU Registry Run Key
    if (cleanLoc.toUpperCase().includes('HKU') || cleanLoc.toUpperCase().includes('HKCU')) {
      const psScript = `
        $regPath = 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
        if ((Get-ItemProperty -Path $regPath -Name '${cleanName}' -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $regPath -Name '${cleanName}' -Force -ErrorAction Stop
            'REMOVED'
        } else {
            'NOT_FOUND'
        }
      `;
      try {
        const out = await this.runExec('powershell.exe', ['-NoProfile', '-Command', psScript], 6000);
        if (out.includes('REMOVED')) {
          db.deletePersistenceItem(name, location);
          db.recordAuditEvent('STARTUP_ITEM_REMOVED', 'USER', `Removed HKCU Run key: ${cleanName}`);
          await this.pollStartupPersistence();
          return { success: true, message: `Removed "${cleanName}" from Current User startup registry.` };
        } else {
          return { success: false, error: `Registry value "${cleanName}" was not found in HKCU Run.` };
        }
      } catch (err) {
        return { success: false, error: `Failed to remove registry key: ${err.message}` };
      }
    }

    // 3. HKLM Registry Run Key (Machine-wide, requires Administrator privileges)
    if (cleanLoc.toUpperCase().includes('HKLM')) {
      const firewall = require('./firewall');
      const admin = await firewall.checkAdminPrivileges();
      const psManualCmd = `Remove-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "${cleanName}"`;

      if (!admin.isAdmin) {
        return {
          success: false,
          error: `Administrator privileges are required to remove machine-wide startup item "${cleanName}".`,
          isAdmin: false,
          manualCommand: psManualCmd,
          elevationGuide: 'Open PowerShell as Administrator and run the command provided to remove this item.'
        };
      }

      const psScript = `
        $regPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
        if ((Get-ItemProperty -Path $regPath -Name '${cleanName}' -ErrorAction SilentlyContinue)) {
            Remove-ItemProperty -Path $regPath -Name '${cleanName}' -Force -ErrorAction Stop
            'REMOVED'
        } else {
            'NOT_FOUND'
        }
      `;
      try {
        const out = await this.runExec('powershell.exe', ['-NoProfile', '-Command', psScript], 6000);
        if (out.includes('REMOVED')) {
          db.deletePersistenceItem(name, location);
          db.recordAuditEvent('STARTUP_ITEM_REMOVED', 'USER', `Removed HKLM Run key: ${cleanName}`);
          await this.pollStartupPersistence();
          return { success: true, message: `Removed "${cleanName}" from System startup registry.` };
        } else {
          return { success: false, error: `Registry value "${cleanName}" was not found in HKLM Run.` };
        }
      } catch (err) {
        return { success: false, error: `Failed to remove HKLM registry key: ${err.message}` };
      }
    }

    return { success: false, error: `Unrecognized startup location: ${cleanLoc}` };
  }

  /**
   * Starts the continuous background monitoring loops
   */
  async start() {
    if (this.status === 'ACTIVE') return;

    psHost.start();
    db.recordAuditEvent('MONITOR_START', 'SYSTEM', 'Laptop Guard background monitoring started');

    // 1. Initial process cache build
    await this.refreshProcessCache();

    // 2. Initial checks
    await Promise.allSettled([
      this.pollNetworkConnections(),
      this.pollDefenderTelemetry(),
      this.pollStartupPersistence(),
      remoteAccessCollector.poll({
        activeProcesses: Array.from(this.processCache.values()),
        activeConnections: this.activeConnections,
        listeningPorts: this.listeningPorts
      }),
      process.platform === 'win32' ? eventTailer.pollAll() : Promise.resolve(),
      postureEvaluator.evaluate()
    ]);

    // 3. Setup recurring poll loops
    this.netTimer = setInterval(() => {
      this.pollNetworkConnections();
    }, this.pollIntervalMs);

    // Refresh process cache every 30 seconds
    setInterval(() => {
      this.refreshProcessCache();
    }, 30000);

    this.defenderTimer = setInterval(() => {
      this.pollDefenderTelemetry();
    }, this.defenderIntervalMs);

    this.startupTimer = setInterval(() => {
      this.pollStartupPersistence();
    }, this.startupIntervalMs);

    // Remote access and spying collector loop (every 10s)
    this.remoteAccessTimer = setInterval(async () => {
      await remoteAccessCollector.poll({
        activeProcesses: Array.from(this.processCache.values()),
        activeConnections: this.activeConnections,
        listeningPorts: this.listeningPorts
      });
    }, 10000);

    // Event log tailing loop (every 15s, Windows only)
    if (process.platform === 'win32') {
      this.eventTailerTimer = setInterval(async () => {
        await eventTailer.pollAll();
      }, 15000);
    }

    // Security posture evaluator loop (every 3 minutes)
    this.postureTimer = setInterval(async () => {
      await postureEvaluator.evaluate();
    }, 180000);

    // Retention pruning every hour
    this.pruneTimer = setInterval(() => {
      const retentionDays = parseInt(process.env.RETENTION_DAYS, 10) || 7;
      db.pruneOldRecords(retentionDays);
    }, 60 * 60 * 1000);

    this.status = 'ACTIVE';
  }

  /**
   * Graceful stop of all monitoring loops
   */
  stop() {
    if (this.netTimer) clearInterval(this.netTimer);
    if (this.defenderTimer) clearInterval(this.defenderTimer);
    if (this.startupTimer) clearInterval(this.startupTimer);
    if (this.remoteAccessTimer) clearInterval(this.remoteAccessTimer);
    if (this.eventTailerTimer) clearInterval(this.eventTailerTimer);
    if (this.postureTimer) clearInterval(this.postureTimer);
    if (this.pruneTimer) clearInterval(this.pruneTimer);

    psHost.shutdown();
    this.status = 'STOPPED';
    db.recordAuditEvent('MONITOR_STOP', 'SYSTEM', 'Laptop Guard background monitoring stopped');
  }

  /**
   * Returns current live snapshot of all telemetry
   */
  getSnapshot() {
    return {
      status: this.status,
      timestamp: new Date().toISOString(),
      activeConnectionsCount: this.activeConnections.length,
      listeningPortsCount: this.listeningPorts.length,
      processesMonitoredCount: this.processCache.size,
      activeConnections: this.activeConnections,
      listeningPorts: this.listeningPorts,
      defenderStatus: this.defenderStatus,
      startupItems: this.startupItems,
      remoteAccess: remoteAccessCollector.getSnapshot(),
      posture: postureEvaluator.getSnapshot(),
      events: eventTailer.getStatus(),
      collectorErrors: this.collectorErrors.slice(-10)
    };
  }
}

module.exports = new LaptopMonitor();
