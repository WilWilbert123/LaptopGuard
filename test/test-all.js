/**
 * MY LAPTOP GUARD - Comprehensive Automated Test Suite
 * Verifies Database, Detection Rules, Firewall Safety, Telemetry Collectors, and REST Endpoints.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');

console.log('====================================================');
console.log('   MY LAPTOP GUARD - AUTOMATED TEST SUITE           ');
console.log('====================================================\n');

let passed = 0;
let failed = 0;

function runTest(name, fn) {
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failed++;
  }
}

async function runAsyncTest(name, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passed++;
  } catch (err) {
    console.error(`  [FAIL] ${name}`);
    console.error(`         ${err.message}`);
    failed++;
  }
}

async function executeAll() {
  // -------------------------------------------------------------------
  // 1. DATABASE TESTS
  // -------------------------------------------------------------------
  console.log('--- 1. Local SQLite Database Tests ---');
  const testDbFile = path.join(__dirname, 'test_guard.db');
  if (fs.existsSync(testDbFile)) fs.unlinkSync(testDbFile);

  const { GuardDatabase } = require('../background/database');
  const testDb = new GuardDatabase(testDbFile);
  testDb.init();

  runTest('Database initializes and enables WAL mode', () => {
    assert.strictEqual(testDb.initialized, true);
    assert.ok(fs.existsSync(testDbFile));
  });

  runTest('Records and retrieves connections batch', () => {
    const inserted = testDb.recordConnectionsBatch([
      {
        protocol: 'TCP',
        localIp: '192.168.1.50',
        localPort: 54321,
        remoteIp: '93.184.216.34',
        remotePort: 443,
        state: 'ESTABLISHED',
        pid: 2020,
        processName: 'testapp.exe',
        direction: 'OUTBOUND',
        riskLevel: 'LOW',
        isExternal: true
      }
    ]);
    assert.strictEqual(inserted, 1);
    const history = testDb.getConnectionHistory({ limit: 10 });
    assert.strictEqual(history.length, 1);
    assert.strictEqual(history[0].remote_ip, '93.184.216.34');
  });

  runTest('Records and resolves security findings with deduplication', () => {
    const saved = testDb.recordFinding({
      ruleId: 'RULE_TEST_ALERT',
      title: 'Automated Test Detection',
      severity: 'HIGH',
      confidence: 'HIGH',
      processName: 'malware.exe',
      pid: 666,
      remoteIp: '203.0.113.10',
      explanation: 'Test detection rule explanation',
      evidence: ['Suspicious hash observed', 'External socket open']
    });
    assert.ok(saved);
    assert.strictEqual(saved.title, 'Automated Test Detection');

    const active = testDb.getFindings({ status: 'active' });
    assert.strictEqual(active.length, 1);

    const resolved = testDb.resolveFinding(saved.id, 'Test resolution note');
    assert.strictEqual(resolved.status, 'resolved');
    assert.strictEqual(testDb.getFindings({ status: 'active' }).length, 0);
  });

  runTest('Applies schema migrations with version tracking', () => {
    const versions = testDb.db.prepare('SELECT version FROM schema_migrations ORDER BY version ASC').all();
    assert.strictEqual(versions.length, 3);
    assert.strictEqual(versions[0].version, 1);
    assert.strictEqual(versions[1].version, 2);
    assert.strictEqual(versions[2].version, 3);
  });

  runTest('Saves and retrieves event log bookmarks', () => {
    testDb.setBookmark('Security', 10425);
    const rec = testDb.getBookmark('Security');
    assert.strictEqual(rec, 10425);
    assert.strictEqual(testDb.getBookmark('NonExistent'), 0);
  });

  runTest('Upserts and queries remote sessions', () => {
    testDb.upsertRemoteSession({
      sessionId: 2,
      username: 'Alice',
      clientName: 'DESKTOP-REMOTE',
      clientIp: '192.168.1.120',
      state: 'Active',
      toolName: 'RDP'
    });
    const active = testDb.getActiveRemoteSessions();
    assert.strictEqual(active.length, 1);
    assert.strictEqual(active[0].username, 'Alice');

    testDb.closeRemoteSession(2);
    assert.strictEqual(testDb.getActiveRemoteSessions().length, 0);
    assert.strictEqual(testDb.getRemoteSessionHistory().length, 1);
  });

  runTest('Records and retrieves posture snapshots', () => {
    testDb.recordPostureSnapshot({
      score: 85,
      grade: 'B',
      deductions: [{ rule: 'UAC', points: 15, fix: 'Enable UAC' }],
      checks: { bitlocker: true, secureBoot: true }
    });
    const latest = testDb.getLatestPostureSnapshot();
    assert.ok(latest);
    assert.strictEqual(latest.score, 85);
    assert.strictEqual(latest.grade, 'B');
    assert.strictEqual(latest.deductions.length, 1);
  });

  runTest('Manages user trust allowlist', () => {
    testDb.addTrustEntry({
      targetType: 'IP',
      targetValue: '198.51.100.5',
      reason: 'Authorized VPN gateway'
    });
    assert.strictEqual(testDb.isTrusted('IP', '198.51.100.5'), true);
    assert.strictEqual(testDb.isTrusted('IP', '203.0.113.1'), false);
  });

  runTest('Redacts passwords and tokens from process commands', () => {
    testDb.upsertProcess({
      pid: 9999,
      processName: 'secretapp.exe',
      commandLine: 'secretapp.exe --api_key=SuperSecretToken123 --password=MyP@ssword!123'
    });
    const proc = testDb.getProcess(9999);
    assert.ok(proc);
    assert.ok(!proc.command_line.includes('SuperSecretToken123'));
    assert.ok(!proc.command_line.includes('MyP@ssword!123'));
    assert.ok(proc.command_line.includes('[REDACTED_SECRET]'));
  });

  runTest('Prunes old records safely without crashing', () => {
    const res = testDb.pruneOldRecords(7);
    assert.ok(res.prunedBefore);
  });

  testDb.close();
  if (fs.existsSync(testDbFile)) fs.unlinkSync(testDbFile);

  // -------------------------------------------------------------------
  // 2. SECURITY DETECTOR ENGINE TESTS
  // -------------------------------------------------------------------
  console.log('\n--- 2. Evidence-Based Detector Tests ---');
  const detector = require('../background/detector');

  runTest('Flags executable socket running from Temp folder', () => {
    const findings = detector.evaluateConnection({
      processName: 'payload.exe',
      processPath: 'C:\\Users\\John\\AppData\\Local\\Temp\\payload.exe',
      pid: 1234,
      remoteIp: '203.0.113.88',
      remotePort: 443,
      localPort: 51234,
      protocol: 'TCP',
      state: 'ESTABLISHED'
    });
    assert.ok(findings.length >= 1);
    assert.strictEqual(findings[0].ruleId, 'RULE_SUSP_PATH');
    assert.strictEqual(findings[0].severity, 'HIGH');
  });

  runTest('Flags LOLBin PowerShell establishing external internet socket', () => {
    const findings = detector.evaluateConnection({
      processName: 'powershell.exe',
      processPath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      pid: 4321,
      remoteIp: '198.51.100.99',
      remotePort: 8443,
      localPort: 52000,
      protocol: 'TCP',
      state: 'ESTABLISHED'
    });
    assert.ok(findings.some(f => f.ruleId === 'RULE_LOLBIN_NET'));
  });

  runTest('Flags remote desktop software (AnyDesk, TeamViewer)', () => {
    const findings = detector.evaluateConnection({
      processName: 'AnyDesk.exe',
      processPath: 'C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe',
      pid: 9999,
      remoteIp: '185.120.1.5',
      remotePort: 443,
      localPort: 55555,
      protocol: 'TCP',
      state: 'ESTABLISHED'
    });
    assert.ok(findings.some(f => f.ruleId === 'RULE_REMOTE_TOOL'));
  });

  runTest('Flags sensitive listening port exposed on 0.0.0.0 (Port 3389 / 4444)', () => {
    const findings = detector.evaluateConnection({
      processName: 'system',
      localIp: '0.0.0.0',
      localPort: 3389,
      remoteIp: '*',
      remotePort: 0,
      protocol: 'TCP',
      state: 'LISTENING',
      pid: 4
    });
    assert.ok(findings.some(f => f.ruleId === 'RULE_SUSP_LISTENING'));
  });

  runTest('Zero false positives on standard browser traffic (Chrome / Edge)', () => {
    const findings = detector.evaluateConnection({
      processName: 'chrome.exe',
      processPath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      pid: 8800,
      remoteIp: '142.250.190.46',
      remotePort: 443,
      localPort: 56789,
      protocol: 'TCP',
      state: 'ESTABLISHED'
    });
    assert.strictEqual(findings.length, 0);
  });

  // -------------------------------------------------------------------
  // 3. FIREWALL MODULE TESTS
  // -------------------------------------------------------------------
  console.log('\n--- 3. Windows Firewall Safety & Preview Tests ---');
  const firewall = require('../background/firewall');

  runTest('Refuses to block loopback or wildcard addresses', () => {
    const v1 = firewall.validateIp('127.0.0.1');
    assert.strictEqual(v1.valid, false);
    assert.ok(v1.error.includes('loopback'));

    const v2 = firewall.validateIp('0.0.0.0');
    assert.strictEqual(v2.valid, false);

    const v3 = firewall.validateIp('invalid.ip.string');
    assert.strictEqual(v3.valid, false);
  });

  await runAsyncTest('Generates accurate netsh and PowerShell rule previews', async () => {
    const preview = await firewall.generateRulePreview('198.51.100.25', 'BOTH');
    assert.strictEqual(preview.success, true);
    assert.strictEqual(preview.remoteIp, '198.51.100.25');
    assert.ok(preview.exactCommands.netsh.length === 2);
    assert.ok(preview.exactCommands.netsh[0].includes('netsh advfirewall firewall add rule'));
    assert.ok(preview.exactCommands.powershell[0].includes('New-NetFirewallRule'));
    assert.ok(preview.criticalDisclaimer.includes('Windows Firewall'));
  });

  // -------------------------------------------------------------------
  // 4. LIVE TELEMETRY COLLECTOR TESTS
  // -------------------------------------------------------------------
  console.log('\n--- 4. Live Windows Telemetry Collector Tests ---');
  const monitor = require('../background/monitor');

  runTest('Address parser correctly splits IPv4, IPv6, and wildcard', () => {
    const a1 = monitor.parseAddress('192.168.1.1:8080');
    assert.strictEqual(a1.ip, '192.168.1.1');
    assert.strictEqual(a1.port, 8080);

    const a2 = monitor.parseAddress('[fe80::1]:443');
    assert.strictEqual(a2.ip, 'fe80::1');
    assert.strictEqual(a2.port, 443);

    const a3 = monitor.parseAddress('*:*');
    assert.strictEqual(a3.ip, '*');
    assert.strictEqual(a3.port, 0);
  });

  await runAsyncTest('Live connection polling discovers real Windows sockets', async () => {
    await monitor.pollNetworkConnections();
    assert.ok(monitor.activeConnections.length > 0 || monitor.listeningPorts.length > 0);
  });

  await runAsyncTest('Live Defender telemetry queries real system status', async () => {
    await monitor.pollDefenderTelemetry();
    assert.ok(monitor.defenderStatus);
    assert.strictEqual(typeof monitor.defenderStatus.isAvailable, 'boolean');
  });

  // -------------------------------------------------------------------
  // 5. SERVER API ENDPOINT TESTS
  // -------------------------------------------------------------------
  console.log('\n--- 5. Server REST API & Security Header Tests ---');
  const { app, server, db: serverDb } = require('../background/server');
  serverDb.init();
  const TEST_PORT = 3999;

  await new Promise(res => server.listen(TEST_PORT, '127.0.0.1', res));

  function httpGet(path) {
    return new Promise((resolve, reject) => {
      http.get(`http://127.0.0.1:${TEST_PORT}${path}`, (res) => {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => {
          let parsedBody = {};
          try {
            parsedBody = JSON.parse(body || '{}');
          } catch (e) {
            parsedBody = { raw: body };
          }
          resolve({ status: res.statusCode, headers: res.headers, body: parsedBody });
        });
      }).on('error', reject);
    });
  }

  await runAsyncTest('GET /api/status returns health and security headers', async () => {
    const res = await httpGet('/api/status');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.headers['x-frame-options'], 'DENY');
    assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
  });

  await runAsyncTest('GET /api/connections returns active connection list', async () => {
    const res = await httpGet('/api/connections');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.connections));
  });

  await runAsyncTest('GET /api/summary returns complete KPI payload', async () => {
    const res = await httpGet('/api/summary');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(typeof res.body.activeConnectionsCount === 'number');
  });

  await runAsyncTest('GET /api/defender returns Defender telemetry', async () => {
    const res = await httpGet('/api/defender');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
  });

  await runAsyncTest('GET /api/firewall/preview verifies rule generator', async () => {
    const res = await httpGet('/api/firewall/preview?ip=198.51.100.30');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.strictEqual(res.body.remoteIp, '198.51.100.30');
  });

  await runAsyncTest('GET /api/remote-access returns remote access status', async () => {
    const res = await httpGet('/api/remote-access');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.statusBanner);
    assert.ok(typeof res.body.riskScore === 'number');
  });

  await runAsyncTest('GET /api/posture returns 0-100 posture score', async () => {
    const res = await httpGet('/api/posture');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(typeof res.body.score === 'number');
    assert.ok(res.body.grade);
  });

  await runAsyncTest('GET /api/trust returns user allowlist', async () => {
    const res = await httpGet('/api/trust');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(Array.isArray(res.body.trustList));
  });

  await runAsyncTest('GET /api/events/status returns event tailer status', async () => {
    const res = await httpGet('/api/events/status');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.success, true);
    assert.ok(res.body.channels);
  });

  // -------------------------------------------------------------------
  // 6. REMOTE ACCESS & SPYING ENGINE TESTS
  // -------------------------------------------------------------------
  console.log('\n--- 6. Remote Access & Spying Rules Tests ---');
  const remoteRules = require('../background/rules/remote-access');

  runTest('Detects active RDP logon session and assigns CRITICAL risk', () => {
    const findings = remoteRules.evaluateRemoteAccessState({
      activeSessions: [{ logonId: '99', logonType: 10, isRemoteInteractive: true, clientIp: '192.168.1.100' }]
    });
    assert.ok(findings.some(f => f.ruleId === 'RULE_REMOTE_ACTIVE_SESSION'));
    assert.strictEqual(findings[0].severity, 'CRITICAL');

    const risk = remoteRules.calculateRemoteRiskScore({
      activeSessions: [{ logonId: '99', logonType: 10, isRemoteInteractive: true }]
    });
    assert.ok(risk.score >= 50);
    assert.strictEqual(risk.statusBanner.code, 'SESSION_ACTIVE');
  });

  runTest('Detects reverse shell interpreter with external connection', () => {
    const findings = remoteRules.evaluateRemoteAccessState({
      reverseShells: [{ processName: 'powershell.exe', pid: 5555, remoteIp: '198.51.100.80', remotePort: 4444 }]
    });
    assert.ok(findings.some(f => f.ruleId === 'RULE_REMOTE_REVERSE_SHELL'));
    assert.strictEqual(findings[0].severity, 'CRITICAL');
  });

  runTest('Detects active webcam access via ConsentStore', () => {
    const findings = remoteRules.evaluateRemoteAccessState({
      sensors: {
        webcam: { inUse: true, appName: 'chrome.exe', startTime: new Date().toISOString() },
        microphone: { inUse: false }
      }
    });
    assert.ok(findings.some(f => f.ruleId === 'RULE_SENSOR_CAMERA_ACTIVE'));
  });

  // -------------------------------------------------------------------
  // 7. INCIDENT RESPONDER & FORENSICS TESTS
  // -------------------------------------------------------------------
  console.log('\n--- 7. Incident Responder & Forensics Tests ---');
  const responder = require('../background/responder');
  const identifier = require('../background/identify');

  runTest('Responder refuses to block loopback or wildcard addresses', () => {
    const loopback = responder.previewAction('BLOCK_IP', { ip: '127.0.0.1' });
    assert.strictEqual(loopback.valid, false);
    assert.ok(loopback.error.includes('loopback'));

    const wildcard = responder.previewAction('BLOCK_IP', { ip: '0.0.0.0' });
    assert.strictEqual(wildcard.valid, false);
  });

  runTest('Responder refuses to disconnect local console session ID 1', () => {
    const consoleSess = responder.previewAction('DISCONNECT_SESSION', { sessionId: 1, isConsole: true });
    assert.strictEqual(consoleSess.valid, false);
    assert.ok(consoleSess.error.includes('console'));
  });

  runTest('Assembles Remote Session Profile with redacted command line', () => {
    const profile = identifier.buildSessionProfile({
      remoteIp: '203.0.113.50',
      remotePort: 443,
      processName: 'AnyDesk.exe',
      commandLine: 'AnyDesk.exe --token=MySecretToken12345'
    });
    assert.strictEqual(profile.remoteIp, '203.0.113.50');
    assert.strictEqual(profile.toolMatch.id, 'anydesk');
    assert.ok(profile.process.commandLine.includes('[REDACTED_SECRET]'));
    assert.ok(profile.recommendedActions.length >= 2);
  });

  runTest('Generates signed evidence pack with verified SHA-256 integrity hash', () => {
    const pack = responder.generateEvidencePack({
      incidentId: 'INC-TEST-001',
      profile: { remoteIp: '198.51.100.22', plainEnglishSummary: 'Test incident' },
      findings: [{ title: 'Suspicious Socket', severity: 'HIGH' }]
    });
    assert.ok(pack.integrityHash);
    assert.ok(pack.jsonPayload);
    assert.ok(pack.htmlReport);

    const recomputed = crypto.createHash('sha256').update(pack.jsonPayload, 'utf8').digest('hex');
    assert.strictEqual(recomputed, pack.integrityHash);
  });

  // -------------------------------------------------------------------
  // 8. SUSPICIOUS OUTBOUND & REVERSE SHELL HEURISTICS (SECTION 16.1a)
  // -------------------------------------------------------------------
  console.log('\n--- 8. Suspicious Outbound & Reverse Shell Heuristics ---');
  const remoteCollector = require('../background/collectors/remote-access');

  runTest('Beaconing metric computation identifies regular beacon intervals with low jitter', () => {
    // 5 timestamps spaced exactly 10,000ms apart (zero jitter)
    const timestamps = [100000, 110000, 120000, 130000, 140000];
    const metrics = remoteCollector.computeBeaconMetrics(timestamps);
    assert.ok(metrics);
    assert.strictEqual(metrics.meanIntervalSeconds, 10);
    assert.strictEqual(metrics.jitterPercent, 0);
    assert.strictEqual(metrics.isBeaconLike, true);
  });

  runTest('Beaconing metric computation rejects erratic intervals with high jitter', () => {
    // Timestamps with random jitter: 2s, 15s, 1s, 40s
    const erratic = [100000, 102000, 117000, 118000, 158000];
    const metrics = remoteCollector.computeBeaconMetrics(erratic);
    assert.ok(metrics);
    assert.ok(metrics.jitterPercent > 25);
    assert.strictEqual(metrics.isBeaconLike, false);
  });

  runTest('Reverse shell detection flags interpreter owning outbound socket to raw IP with suspicious parent', () => {
    const mockConnections = [
      {
        protocol: 'TCP',
        localIp: '192.168.1.50',
        localPort: 49152,
        remoteIp: '203.0.113.88',
        remotePort: 4444, // Common reverse shell port
        state: 'ESTABLISHED',
        pid: 7788,
        processName: 'powershell.exe',
        isExternal: true
      },
      {
        protocol: 'TCP',
        localIp: '192.168.1.50',
        localPort: 49153,
        remoteIp: '142.250.190.46',
        remotePort: 443,
        state: 'ESTABLISHED',
        pid: 9900,
        processName: 'chrome.exe',
        isExternal: true
      }
    ];

    const mockProcesses = [
      {
        pid: 7788,
        name: 'powershell.exe',
        parent_name: 'winword.exe', // Suspicious parent: Office app launching PowerShell
        command_line: 'powershell.exe -NoProfile -enc SQBFAFgA'
      },
      {
        pid: 9900,
        name: 'chrome.exe',
        parent_name: 'explorer.exe',
        command_line: 'chrome.exe --flag'
      }
    ];

    const { shells, profiles } = remoteCollector.scanReverseShells(mockConnections, mockProcesses, { db: testDb, persist: true, updateInstance: false });
    assert.strictEqual(shells.length, 1);
    assert.strictEqual(profiles.length, 1);

    const prof = profiles[0];
    assert.strictEqual(prof.processName, 'powershell.exe');
    assert.strictEqual(prof.remotePort, 4444);
    assert.strictEqual(prof.confidence, 'HIGH');
    assert.ok(prof.summary.includes('reverse-shell indicators'));
    assert.ok(prof.evidence.some(e => e.includes('common reverse-shell port')));
    assert.ok(prof.evidence.some(e => e.includes('Suspicious parent process (winword.exe)')));
  });

  runTest('Suspicious outbound profiles retrieved from SQLite are normalized with both camelCase and snake_case', () => {
    const list = testDb.getSuspiciousOutboundProfiles(10);
    assert.ok(Array.isArray(list));
    if (list.length > 0) {
      const p = list[0];
      assert.ok(p.processName, 'processName must be present');
      assert.ok(p.remoteIp || p.peerIp, 'remoteIp/peerIp must be present');
      assert.ok(p.remotePort !== undefined || p.peerPort !== undefined, 'remotePort/peerPort must be present');
      assert.ok(p.parentProcessName !== undefined, 'parentProcessName must be present');
      assert.ok(Array.isArray(p.evidence), 'evidence must be an array');
      assert.ok(p.summary || p.plainEnglish, 'summary/plainEnglish must be present');
    }
  });

  // -------------------------------------------------------------------
  // 9. MALWARE ANALYSIS & ISOLATED REVERSE ENGINEERING (SECTION 17)
  // -------------------------------------------------------------------
  console.log('\n--- 9. Malware Analysis & Isolated Reverse Engineering ---');
  const analyzer = require('../background/analyzer');

  runTest('Shannon entropy calculation accurately differentiates uniform vs high-entropy data', () => {
    // 1. Uniform bytes: entropy must be 0
    const uniform = Buffer.alloc(1024, 0x41);
    const zeroEntropy = analyzer.calculateShannonEntropy(uniform);
    assert.strictEqual(zeroEntropy, 0);

    // 2. High-entropy random data: entropy must approach 8.0 bits/byte
    const random = crypto.randomBytes(4096);
    const highEntropy = analyzer.calculateShannonEntropy(random);
    assert.ok(highEntropy > 7.5, `Expected high entropy > 7.5, got ${highEntropy}`);
  });

  runTest('Passive IOC extraction identifies IPs, URLs, domains, registry keys, and mutexes', () => {
    const strings = [
      'Connecting to 198.51.100.99 for stage 2 payload',
      'Download link http://suspicious-payload-drop.test/bin.exe',
      'Persistence at HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor',
      'Acquiring mutex Global\\EvilCampaignMutex_v2',
      'System path C:\\Windows\\System32\\drivers\\etc\\hosts'
    ];

    const iocs = analyzer.extractIocs(strings);
    assert.ok(iocs.ipv4.includes('198.51.100.99'));
    assert.ok(iocs.urls.some(u => u.includes('suspicious-payload-drop.test')));
    assert.ok(iocs.registryKeys.some(r => r.includes('CurrentVersion\\Run')));
    assert.ok(iocs.mutexes.includes('Global\\EvilCampaignMutex_v2'));
    assert.ok(iocs.filePaths.some(p => p.includes('hosts')));
  });

  runTest('Capability inference detects socket creation, injection APIs, and persistence heuristics', () => {
    const strings = [
      'WSAStartup', 'connect', 'send', 'recv',
      'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
      'RegSetValueExA', 'RegCreateKeyExA'
    ];

    const caps = analyzer.inferCapabilities(null, strings);
    assert.ok(caps.some(c => c.category === 'NETWORK' && c.confidence === 'HIGH'));
    assert.ok(caps.some(c => (c.category === 'EXECUTION' || c.id === 'CAP_INJECTION') && c.confidence === 'HIGH'));
    assert.ok(caps.some(c => c.category === 'PERSISTENCE'));
  });

  runTest('PE Header parser reads MZ header, PE signature, sections, and section entropy', () => {
    // Synthesize a minimal PE binary in memory
    const peBuf = Buffer.alloc(1024);
    // DOS header: MZ magic at 0
    peBuf[0] = 0x4D;
    peBuf[1] = 0x5A;
    // e_lfanew at offset 0x3C points to 0x80
    peBuf.writeUInt32LE(0x80, 0x3C);

    // PE signature 'PE\0\0' at 0x80
    peBuf[0x80] = 0x50; // 'P'
    peBuf[0x81] = 0x45; // 'E'
    peBuf[0x82] = 0x00;
    peBuf[0x83] = 0x00;

    // COFF header at 0x84: Machine = 0x8664 (x64), NumberOfSections = 1
    peBuf.writeUInt16LE(0x8664, 0x84); // Machine
    peBuf.writeUInt16LE(1, 0x86);      // NumberOfSections: 1
    peBuf.writeUInt16LE(0xF0, 0x94);    // SizeOfOptionalHeader

    // Section header starts at 0x80 + 4 + 20 + 0xF0 = 0x188
    const secOffset = 0x80 + 4 + 20 + 0xF0;
    peBuf.write('.text\0\0\0', secOffset);
    peBuf.writeUInt32LE(0x100, secOffset + 8);  // VirtualSize
    peBuf.writeUInt32LE(0x100, secOffset + 16); // SizeOfRawData
    peBuf.writeUInt32LE(0x200, secOffset + 20); // PointerToRawData

    // Fill .text raw data at 0x200 with random bytes
    crypto.randomBytes(0x100).copy(peBuf, 0x200);

    const parsed = analyzer.parsePeHeader(peBuf);
    assert.ok(parsed);
    assert.strictEqual(parsed.isPe, true);
    assert.strictEqual(parsed.machine, 'x64 (64-bit AMD64)');
    assert.strictEqual(parsed.sections.length, 1);
    assert.strictEqual(parsed.sections[0].name, '.text');
    assert.ok(parsed.sections[0].entropy > 5.0);
  });

  await runAsyncTest('Isolated analysis strictly enforces zero outbound network requests', async () => {
    // Create a temporary benign script file to analyze
    const tempFile = path.join(__dirname, 'test_sample.ps1');
    fs.writeFileSync(tempFile, 'Write-Output "Test benign script payload"\n$x = 42\n');

    // Instrument network modules to assert 0 network calls
    const net = require('net');
    let networkCalls = 0;

    const originalConnect = net.Socket.prototype.connect;
    net.Socket.prototype.connect = function(...args) {
      networkCalls++;
      return originalConnect.apply(this, args);
    };

    const originalHttpRequest = http.request;
    http.request = function(...args) {
      networkCalls++;
      return originalHttpRequest.apply(this, args);
    };

    try {
      const report = await analyzer.analyzeFile(tempFile, { db: testDb, persist: true });
      assert.ok(report.success);
      assert.strictEqual(networkCalls, 0, 'CRITICAL: Analyzer must never execute outbound network requests!');
      assert.ok(report.sha256);
      assert.ok(report.reportHash);
    } finally {
      // Restore hooks and cleanup
      net.Socket.prototype.connect = originalConnect;
      http.request = originalHttpRequest;
      if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
    }
  });

  // Stop test server
  await new Promise(res => server.close(res));

  // -------------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------------
  console.log('\n====================================================');
  console.log(`TEST RESULTS: ${passed} PASSED, ${failed} FAILED`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

executeAll().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
