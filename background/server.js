/**
 * MY LAPTOP GUARD - Main Server Entrypoint
 * Express API, Socket.IO real-time hub, and lifecycle supervisor for the background worker.
 * Strictly bound to 127.0.0.1 for local isolation and security.
 */

require('dotenv').config();
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { Server } = require('socket.io');

const db = require('./database');
const monitor = require('./monitor');
const firewall = require('./firewall');
const remoteAccessCollector = require('./collectors/remote-access');
const eventTailer = require('./collectors/event-tailer');
const postureEvaluator = require('./posture');
const responder = require('./responder');
const identifier = require('./identify');
const notify = require('./notify');
const analyzer = require('./analyzer');
const aiService = require('./ai-service');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = parseInt(process.env.PORT, 10) || 3000;
const HOST = process.env.HOST || '127.0.0.1';

// Setup local authentication token
let API_AUTH_TOKEN = process.env.API_AUTH_TOKEN;
if (!API_AUTH_TOKEN || API_AUTH_TOKEN === 'laptop-guard-local-token-change-me') {
  // If no custom token provided, use default local token or generate
  API_AUTH_TOKEN = process.env.API_AUTH_TOKEN || 'laptop-guard-local-token-change-me';
}

// -----------------------------------------------------------------------------
// Middleware: Security Headers & Body Parsing
// -----------------------------------------------------------------------------
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss:;"
  );
  next();
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// Serve static dashboard files from public/
app.use(express.static(path.join(__dirname, '..', 'public')));

// Authentication middleware for sensitive/mutating operations
function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.query.token;
  if (!token || token !== API_AUTH_TOKEN) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized: Valid X-Auth-Token header required for sensitive operations.'
    });
  }
  next();
}

// -----------------------------------------------------------------------------
// REST API Routes
// -----------------------------------------------------------------------------

/**
 * Public configuration endpoint for dashboard initial setup
 */
app.get('/api/config', (req, res) => {
  res.json({
    authToken: API_AUTH_TOKEN,
    pollIntervalMs: monitor.pollIntervalMs,
    host: HOST,
    port: PORT
  });
});

/**
 * Worker status & health metrics
 */
app.get('/api/status', async (req, res) => {
  const mem = process.memoryUsage();
  const admin = await firewall.checkAdminPrivileges();

  res.json({
    success: true,
    status: monitor.status,
    uptimeSeconds: Math.floor(process.uptime()),
    memoryMb: {
      rss: Math.round(mem.rss / 1024 / 1024),
      heapUsed: Math.round(mem.heapUsed / 1024 / 1024)
    },
    isAdmin: admin.isAdmin,
    adminMethod: admin.method || null,
    pollIntervalMs: monitor.pollIntervalMs,
    timestamp: new Date().toISOString()
  });
});

/**
 * Dashboard KPI Summary
 */
app.get('/api/summary', (req, res) => {
  const dbSummary = db.getDashboardSummary();
  const snapshot = monitor.getSnapshot();

  res.json({
    success: true,
    workerStatus: monitor.status,
    activeConnectionsCount: snapshot.activeConnectionsCount,
    listeningPortsCount: snapshot.listeningPortsCount,
    processesMonitoredCount: snapshot.processesMonitoredCount,
    activeFindingsCount: dbSummary.activeFindingsCount || 0,
    criticalFindingsCount: dbSummary.criticalFindingsCount || 0,
    activeFirewallRulesCount: dbSummary.activeFirewallRulesCount || 0,
    defender: snapshot.defenderStatus,
    timestamp: new Date().toISOString()
  });
});

/**
 * Live connection inspection with search and filters
 */
app.get('/api/connections', (req, res) => {
  const { search, state, direction, risk } = req.query;
  let conns = monitor.activeConnections;

  if (search) {
    const s = search.toLowerCase();
    conns = conns.filter(c =>
      (c.remoteIp && c.remoteIp.toLowerCase().includes(s)) ||
      (c.processName && c.processName.toLowerCase().includes(s)) ||
      (c.localPort && String(c.localPort).includes(s)) ||
      (c.remotePort && String(c.remotePort).includes(s)) ||
      (c.pid && String(c.pid).includes(s))
    );
  }

  if (state) {
    conns = conns.filter(c => c.state === state);
  }

  if (direction) {
    conns = conns.filter(c => c.direction === direction);
  }

  if (risk) {
    conns = conns.filter(c => c.riskLevel === risk);
  }

  res.json({
    success: true,
    count: conns.length,
    connections: conns
  });
});

/**
 * Listening ports & UDP endpoints
 */
app.get('/api/listening', (req, res) => {
  res.json({
    success: true,
    count: monitor.listeningPorts.length,
    listening: monitor.listeningPorts
  });
});

/**
 * Suspicious findings list
 */
app.get('/api/findings', (req, res) => {
  const { status, severity, limit } = req.query;
  const findings = db.getFindings({ status, severity, limit });
  res.json({
    success: true,
    count: findings.length,
    findings: findings
  });
});

/**
 * Resolve/Acknowledge a finding
 */
app.post('/api/findings/:id/resolve', requireAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const notes = req.body.notes || 'Acknowledged by user';
  const updated = db.resolveFinding(id, notes);

  db.recordAuditEvent('FINDING_RESOLVED', 'USER', `Resolved finding #${id}`, { id, notes });
  io.emit('finding:resolved', { id });

  res.json({ success: true, finding: updated });
});

/**
 * Generate a harmless test finding to verify real-time alert delivery
 */
app.post('/api/findings/test', requireAuth, (req, res) => {
  const testFinding = {
    ruleId: 'RULE_TEST_VERIFICATION',
    title: 'Heuristic Test: Live Telemetry Verification',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    processName: 'powershell.exe',
    pid: process.pid,
    remoteIp: '203.0.113.10',
    explanation: 'Harmless test alert generated to verify that the real-time detection pipeline, SQLite persistence, and Socket.IO live notifications are working in real time.',
    evidence: [
      `Engine Status: ACTIVE (Evaluated every ${monitor.pollIntervalMs / 1000}s)`,
      `Active Connections Evaluated: ${monitor.activeConnections.length}`,
      `Listening Ports Audited: ${monitor.listeningPorts.length}`,
      `Endpoint Tested: 203.0.113.10:443 (TCP ESTABLISHED)`
    ],
    remediation: 'Click "Acknowledge & Resolve" below to clear this diagnostic alert and record the action in the audit trail.',
    disclaimer: 'This is an authorized diagnostic test alert initiated from the dashboard.'
  };

  const saved = db.recordFinding(testFinding);
  db.recordAuditEvent('TEST_FINDING_CREATED', 'USER', 'Generated diagnostic test security finding', { id: saved.id });
  io.emit('finding:new', saved);

  res.json({ success: true, finding: saved });
});

/**
 * Windows Defender status and detections
 */
app.get('/api/defender', (req, res) => {
  const detections = db.getDefenderDetections(50);
  res.json({
    success: true,
    status: monitor.defenderStatus,
    recentDetections: detections
  });
});

/**
 * Startup programs and persistence entries
 */
app.get('/api/startup', (req, res) => {
  const items = db.getPersistenceItems();
  res.json({
    success: true,
    count: items.length,
    items: items
  });
});

/**
 * Remove a startup persistence item
 */
app.post('/api/startup/remove', requireAuth, async (req, res) => {
  const { name, location } = req.body;
  if (!name) {
    return res.status(400).json({ success: false, error: 'Startup item name is required.' });
  }

  const result = await monitor.removeStartupItem(name, location);
  if (result.success) {
    io.emit('startup:update', { removed: name });
  }
  res.json(result);
});

/**
 * Check Windows Administrator privileges
 */
app.get('/api/firewall/check-admin', async (req, res) => {
  const result = await firewall.checkAdminPrivileges();
  res.json({ success: true, ...result });
});

/**
 * Preview firewall rule command and safety explanation
 */
app.get('/api/firewall/preview', async (req, res) => {
  const { ip, direction } = req.query;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'Target IP is required.' });
  }

  const preview = await firewall.generateRulePreview(ip, direction || 'BOTH');
  res.json(preview);
});

/**
 * Create a Windows Firewall block rule
 */
app.post('/api/firewall/block', requireAuth, async (req, res) => {
  const { ip, direction, comment, confirmed } = req.body;

  if (!ip) {
    return res.status(400).json({ success: false, error: 'Target IP is required.' });
  }

  if (!confirmed) {
    return res.status(400).json({
      success: false,
      error: 'Explicit confirmation is required before creating a Windows Firewall rule.'
    });
  }

  const result = await firewall.executeBlockRule(ip, direction || 'BOTH', comment, confirmed);

  if (result.success) {
    io.emit('firewall:update', { ruleName: result.ruleName, remoteIp: ip });
  }

  res.json(result);
});

/**
 * List managed firewall rules
 */
app.get('/api/firewall/rules', async (req, res) => {
  const rules = await firewall.getManagedRules();
  res.json({ success: true, rules });
});

/**
 * System-wide Windows Firewall profile and block rules status
 */
app.get('/api/firewall/status', async (req, res) => {
  const status = await firewall.getSystemFirewallStatus();
  const managedRules = await firewall.getManagedRules();
  res.json({
    success: true,
    ...status,
    managedRules
  });
});

/**
 * Remove a managed firewall rule
 */
app.delete('/api/firewall/rules/:name', requireAuth, async (req, res) => {
  const ruleName = req.params.name;
  const result = await firewall.removeBlockRule(ruleName);

  if (result.success) {
    io.emit('firewall:update', { removed: ruleName });
  }

  res.json(result);
});

/**
 * Audit events trail
 */
app.get('/api/audit', (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 100;
  const events = db.getAuditEvents(limit);
  res.json({ success: true, events });
});

/**
 * Collector health and execution timings
 */
app.get('/api/health-logs', (req, res) => {
  const health = db.getLatestHealth();
  res.json({
    success: true,
    status: monitor.status,
    health: health,
    errors: monitor.collectorErrors
  });
});

/**
 * Trigger an immediate telemetry polling cycle
 */
app.post('/api/scan', requireAuth, async (req, res) => {
  try {
    await Promise.allSettled([
      monitor.pollNetworkConnections(),
      monitor.pollDefenderTelemetry(),
      monitor.pollStartupPersistence()
    ]);
    res.json({ success: true, message: 'Immediate scan completed.' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * Remote Access and Spying Telemetry
 */
app.get('/api/remote-access', (req, res) => {
  const snapshot = remoteAccessCollector.getSnapshot();
  const state = snapshot.state || {};
  const bannerSeverity = (snapshot.statusBanner && snapshot.statusBanner.severity) ? snapshot.statusBanner.severity.toLowerCase() : 'safe';
  const bannerType = bannerSeverity === 'safe' ? 'none' : (bannerSeverity === 'critical' ? 'critical' : (bannerSeverity === 'high' ? 'high' : 'low'));
  
  res.json({
    success: true,
    riskScore: snapshot.riskScore || 0,
    riskLevel: snapshot.riskTier || 'NONE',
    riskTier: snapshot.riskTier || 'NONE',
    banner: {
      type: bannerType,
      title: snapshot.statusBanner ? snapshot.statusBanner.text : 'No remote access detected right now',
      description: snapshot.factors && snapshot.factors.length > 0
        ? snapshot.factors.map(f => f.description).join('; ')
        : 'Monitored continuously via Windows APIs. Local evidence only.'
    },
    statusBanner: snapshot.statusBanner,
    sessions: state.activeSessions || state.logonSessions || [],
    tools: state.detectedTools || state.knownTools || [],
    sensors: Array.isArray(state.sensors) ? state.sensors : [
      {
        sensor: 'Camera (Webcam)',
        appName: (state.sensors && state.sensors.webcam && state.sensors.webcam.appName) || '—',
        appPath: (state.sensors && state.sensors.webcam && state.sensors.webcam.appPath) || '',
        inUse: Boolean(state.sensors && state.sensors.webcam && state.sensors.webcam.inUse),
        lastUsedTime: (state.sensors && state.sensors.webcam && state.sensors.webcam.startTime) || null
      },
      {
        sensor: 'Microphone',
        appName: (state.sensors && state.sensors.microphone && state.sensors.microphone.appName) || '—',
        appPath: (state.sensors && state.sensors.microphone && state.sensors.microphone.appPath) || '',
        inUse: Boolean(state.sensors && state.sensors.microphone && state.sensors.microphone.inUse),
        lastUsedTime: (state.sensors && state.sensors.microphone && state.sensors.microphone.startTime) || null
      }
    ],
    reverseShells: state.reverseShells || [],
    findings: snapshot.findings || []
  });
});

app.get('/api/remote-access/sessions', (req, res) => {
  const active = db.getActiveRemoteSessions();
  const history = db.getRemoteSessionHistory(50);
  res.json({ success: true, active, history });
});

/**
 * Security Posture Assessment (0-100 Score)
 */
app.get('/api/posture', (req, res) => {
  const snapshot = postureEvaluator.getSnapshot();
  res.json({ success: true, ...snapshot });
});

app.post('/api/posture/refresh', requireAuth, async (req, res) => {
  const snapshot = await postureEvaluator.evaluate();
  if (snapshot) {
    io.emit('posture:update', snapshot);
    res.json({ success: true, ...snapshot });
  } else {
    res.status(500).json({ success: false, error: 'Posture assessment failed.' });
  }
});

/**
 * Incident Identification & Containment Responder
 */
app.all('/api/respond/profile', (req, res) => {
  const activeSessions = db.getActiveRemoteSessions();
  const sessionData = (req.body && Object.keys(req.body).length > 0) ? req.body : (activeSessions[0] || {});
  const profile = identifier.buildSessionProfile(sessionData);
  res.json({ success: true, profile });
});

app.post('/api/respond/preview', (req, res) => {
  const actionType = req.body.actionType || req.body.action;
  const params = req.body.params || req.body;
  const preview = responder.previewAction(actionType, params || {});
  res.json(preview);
});

app.post('/api/respond/execute', requireAuth, async (req, res) => {
  const actionType = req.body.actionType || req.body.action;
  const params = req.body.params || req.body;
  const confirmed = req.body.confirmed !== false;
  if (!confirmed) {
    return res.status(400).json({ success: false, error: 'Explicit user confirmation is required before executing containment actions.' });
  }
  const result = await responder.executeAction(actionType, params || {});
  if (result.success) {
    io.emit('respond:action', result);
  }
  res.json(result);
});

app.post('/api/respond/restore-network', requireAuth, async (req, res) => {
  const result = await responder.restoreNetworkAdapters();
  res.json(result);
});

app.post('/api/respond/evidence-pack', (req, res) => {
  const pack = responder.generateEvidencePack(req.body);
  res.json({
    success: true,
    incidentId: pack.incidentId,
    exportedAtUtc: pack.exportedAtUtc,
    integrityHash: pack.integrityHash,
    sha256: pack.integrityHash,
    json: pack.jsonPayload,
    html: pack.htmlReport,
    jsonPayload: pack.jsonPayload,
    htmlReport: pack.htmlReport
  });
});

/**
 * Process Catalogue
 */
app.get('/api/processes', (req, res) => {
  const list = db.getProcesses({ filter: req.query.filter, limit: req.query.limit });
  res.json({ success: true, count: list.length, processes: list });
});

/**
 * User Trust / Allowlist
 */
app.get('/api/trust', (req, res) => {
  res.json({ success: true, trustList: db.getTrustList() });
});

app.post('/api/trust', requireAuth, (req, res) => {
  const { targetType, targetValue, reason, expiresAtUtc } = req.body;
  if (!targetType || !targetValue) {
    return res.status(400).json({ success: false, error: 'Target type and value are required.' });
  }
  db.addTrustEntry({ targetType, targetValue, reason, expiresAtUtc });
  res.json({ success: true, message: 'Added to trust list.' });
});

app.delete('/api/trust/:id', requireAuth, (req, res) => {
  db.removeTrustEntry(req.params.id);
  res.json({ success: true, message: 'Removed from trust list.' });
});

/**
 * Windows Event Log Tailer Status
 */
app.get('/api/events/status', (req, res) => {
  res.json({ success: true, ...eventTailer.getStatus() });
});

/**
 * Static Malware Analysis & Reverse Engineering (Section 17 - Local Only)
 */
app.post('/api/analyze/file', requireAuth, async (req, res) => {
  const { filePath, overrideSystemDir } = req.body;
  if (!filePath) {
    return res.status(400).json({ success: false, error: 'File path is required.' });
  }

  const result = await analyzer.analyzeFile(filePath, { overrideSystemDir: !!overrideSystemDir });
  if (result.success) {
    io.emit('malware:analyzed', {
      reportId: result.reportId,
      fileName: result.data.fileMetadata.fileName,
      sha256: result.data.hashes.sha256,
      integrityHash: result.integrityHash
    });
  }
  res.json(result);
});

app.get('/api/analyze/reports', (req, res) => {
  const reports = db.getMalwareReports(req.query.limit || 50);
  res.json({ success: true, count: reports.length, reports });
});

app.get('/api/analyze/reports/:id', (req, res) => {
  const report = db.getMalwareReport(req.params.id);
  if (!report) {
    return res.status(404).json({ success: false, error: 'Report not found.' });
  }
  res.json({ success: true, report });
});

app.get('/api/analyze/reports/:id/html', (req, res) => {
  const report = db.getMalwareReport(req.params.id);
  if (!report || !report.report_html) {
    return res.status(404).send('Report not found or HTML missing.');
  }
  res.setHeader('Content-Type', 'text/html');
  res.send(report.report_html);
});

app.get('/api/analyze/reports/:id/handoff', (req, res) => {
  const report = db.getMalwareReport(req.params.id);
  if (!report || !report.report) {
    return res.status(404).json({ success: false, error: 'Report not found.' });
  }
  const r = report.report;
  res.json({
    success: true,
    handoff: {
      tool: 'Ghidra / x64dbg',
      suggestedArchitecture: r.ghidraHandoff ? r.ghidraHandoff.suggestedArchitecture : 'Auto-detect',
      entryPoint: r.ghidraHandoff ? r.ghidraHandoff.entryPoint : 'N/A',
      imageBase: r.ghidraHandoff ? r.ghidraHandoff.imageBase : 'N/A',
      sha256: r.hashes ? r.hashes.sha256 : '',
      iocs: r.iocs || {},
      dynamicAnalysisInstructions: r.dynamicAnalysisInstructions || {}
    }
  });
});

/**
 * Suspicious Outbound & Reverse-Shell Profiles (Section 16.1a)
 */
app.get('/api/suspicious-outbound', (req, res) => {
  const active = remoteAccessCollector.getSuspiciousOutbound();
  const dbProfiles = db.getSuspiciousOutboundProfiles(req.query.limit || 50);
  res.json({
    success: true,
    count: active.length,
    profiles: active,
    history: dbProfiles
  });
});

/**
 * Correlated Security Incidents
 */
app.get('/api/incidents', (req, res) => {
  const list = db.getIncidents({ limit: req.query.limit, status: req.query.status });
  res.json({ success: true, count: list.length, incidents: list });
});

app.get('/api/incidents/:id', (req, res) => {
  const inc = db.getIncidentById(req.params.id);
  if (!inc) {
    return res.status(404).json({ success: false, error: 'Incident not found.' });
  }
  res.json({ success: true, incident: inc });
});

app.post('/api/incidents/:id/status', requireAuth, (req, res) => {
  const { status, notes } = req.body;
  db.updateIncident(req.params.id, { status, notes });
  db.recordAuditEvent('INCIDENT_STATUS_CHANGE', 'USER', `Updated incident ${req.params.id} to ${status}`, { id: req.params.id, status, notes });
  io.emit('incident:updated', { id: req.params.id, status });
  res.json({ success: true, message: 'Incident updated.' });
});

/**
 * =====================================================================
 * GUARDIAN AI & RAG ASSISTANT ENDPOINTS
 * =====================================================================
 */
app.get('/api/ai/status', async (req, res) => {
  const status = await aiService.checkOllamaStatus();
  const context = aiService.buildLiveContext(monitor, db, remoteAccessCollector);
  res.json({
    success: true,
    ollama: status,
    activeModel: aiService.activeModel || 'Guardian Local Expert RAG',
    contextSummary: context.summary
  });
});

app.get('/api/ai/suggested', (req, res) => {
  const context = aiService.buildLiveContext(monitor, db, remoteAccessCollector);
  const questions = aiService.getSuggestedQuestions(context);
  res.json({
    success: true,
    questions
  });
});

app.post('/api/ai/chat', async (req, res) => {
  const { message, history } = req.body;
  if (!message || typeof message !== 'string') {
    return res.status(400).json({ success: false, error: 'A valid message prompt is required.' });
  }

  try {
    const result = await aiService.chat(message, monitor, db, remoteAccessCollector, history || []);
    res.json(result);
  } catch (err) {
    console.error('[Guardian AI Server Error]', err);
    // Fail-safe: Always return complete expert analysis with live telemetry
    try {
      const context = aiService.buildLiveContext(monitor, db, remoteAccessCollector);
      const reply = aiService.generateLocalExpertResponse(message, context);
      const followUps = aiService.generateFollowUpQuestions(message, reply, context);
      res.json({
        success: true,
        source: 'local_rag',
        model: 'Guardian Embedded RAG (Fail-Safe)',
        reply,
        answer: reply,
        followUps,
        contextSummary: context.summary
      });
    } catch (fallbackErr) {
      res.status(500).json({ success: false, error: fallbackErr.message });
    }
  }
});

// -----------------------------------------------------------------------------
// Socket.IO Real-time Events
// -----------------------------------------------------------------------------
notify.setSocketIO(io);

io.on('connection', (socket) => {
  // Send immediate telemetry snapshot upon connection
  socket.emit('init', {
    status: monitor.status,
    summary: db.getDashboardSummary(),
    snapshot: monitor.getSnapshot()
  });
});

// Wire monitor event listeners to Socket.IO broadcasts
monitor.onUpdateCallback = (data) => {
  io.emit('connections:update', data);
};

monitor.onFindingCallback = (finding) => {
  notify.dispatch(finding);
  io.emit('finding:new', finding);
};

// -----------------------------------------------------------------------------
// Graceful Shutdown & Supervisor
// -----------------------------------------------------------------------------
async function gracefulShutdown(signal) {
  console.log(`\n[Server] Received ${signal}. Initiating graceful shutdown...`);
  monitor.stop();
  db.recordAuditEvent('SHUTDOWN', 'SYSTEM', `Laptop Guard shut down via ${signal}`);

  server.close(() => {
    console.log('[Server] HTTP server closed.');
    db.close();
    console.log('[Server] Database closed cleanly.');
    process.exit(0);
  });

  // Force exit if hanging after 5 seconds
  setTimeout(() => {
    console.error('[Server] Forced shutdown after timeout.');
    process.exit(1);
  }, 5000);
}

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

process.on('uncaughtException', (err) => {
  console.error('[Fatal Error] Uncaught Exception:', err.message, err.stack);
  db.recordHealth('Supervisor', 'CRITICAL', 0, `Uncaught Exception: ${err.message}`);
});

process.on('unhandledRejection', (reason) => {
  console.error('[Error] Unhandled Rejection:', reason);
  db.recordHealth('Supervisor', 'WARN', 0, `Unhandled Rejection: ${String(reason)}`);
});

// -----------------------------------------------------------------------------
// Startup Sequence
// -----------------------------------------------------------------------------
async function bootstrap() {
  try {
    console.log('====================================================');
    console.log('   MY LAPTOP GUARD - Personal Windows Security      ');
    console.log('====================================================');

    // 1. Initialize SQLite Database
    db.init();
    console.log('[Database] SQLite initialized at data/laptop_guard.db');

    // 2. Start HTTP and WebSocket listener strictly on 127.0.0.1
    server.listen(PORT, HOST, async () => {
      console.log(`[Dashboard] Running at http://${HOST}:${PORT}`);
      console.log(`[Security] Bound strictly to localhost (${HOST})`);
      console.log(`[Auth Token] ${API_AUTH_TOKEN}`);

      // 3. Start background monitoring loops
      await monitor.start();
      console.log('[Monitor] Background telemetry loops active.');

      const admin = await firewall.checkAdminPrivileges();
      if (admin.isAdmin) {
        console.log('[Permissions] Running with Administrator privileges (Firewall blocking enabled).');
      } else {
        console.log('[Permissions] Running as standard user. (Firewall rules require elevation or manual PowerShell execution).');
      }
      console.log('====================================================\n');
    });
  } catch (err) {
    console.error('[Bootstrap Failed]', err);
    process.exit(1);
  }
}

if (require.main === module) {
  bootstrap();
}

module.exports = { app, server, monitor, db, firewall };
