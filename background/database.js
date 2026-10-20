/**
 * MY LAPTOP GUARD - Local SQLite Database Module
 * Lightweight, zero-external-dependency persistence using Node.js built-in DatabaseSync.
 * Stores telemetry, findings, processes, firewall actions, and audit logs with bounded retention.
 */

const path = require('path');
const fs = require('fs');
const { redactSensitiveData } = require('./redact');

class GuardDatabase {
  constructor(dbPath) {
    this.dbPath = dbPath || path.join(__dirname, '..', 'data', 'laptop_guard.db');
    this.db = null;
    this.initialized = false;
  }

  /**
   * Initializes SQLite database, applies performance PRAGMAs, and creates schema
   */
  init() {
    if (this.initialized) return;

    // Ensure data directory exists
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Use Node.js built-in DatabaseSync
    const { DatabaseSync } = require('node:sqlite');
    this.db = new DatabaseSync(this.dbPath);

    // Performance & reliability PRAGMAs
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA synchronous = NORMAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA busy_timeout = 5000;');

    this._runMigrations();
    this.initialized = true;
  }

  /**
   * Version-controlled schema migrations. Never drops user data.
   */
  _runMigrations() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL,
        description TEXT NOT NULL
      );
    `);

    const appliedRows = this.db.prepare('SELECT version FROM schema_migrations').all();
    const appliedVersions = new Set(appliedRows.map(r => r.version));

    // Migration 1: Baseline schema
    if (!appliedVersions.has(1)) {
      this.db.exec('BEGIN TRANSACTION');
      try {
        this.db.exec(`
          -- Connection observations
          CREATE TABLE IF NOT EXISTS connections_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            protocol TEXT NOT NULL,
            local_ip TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            remote_ip TEXT NOT NULL,
            remote_port INTEGER NOT NULL,
            state TEXT NOT NULL,
            pid INTEGER NOT NULL,
            process_name TEXT,
            process_path TEXT,
            direction TEXT,
            risk_level TEXT DEFAULT 'LOW',
            is_external INTEGER DEFAULT 0,
            details_json TEXT
          );

          -- Suspicious activity & evidence-based detections
          CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            fingerprint TEXT UNIQUE NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            process_name TEXT,
            pid INTEGER,
            remote_ip TEXT,
            explanation TEXT NOT NULL,
            evidence_json TEXT,
            remediation TEXT,
            status TEXT DEFAULT 'active',
            resolved_at TEXT,
            resolved_notes TEXT
          );

          -- Known process catalogue
          CREATE TABLE IF NOT EXISTS processes (
            pid INTEGER NOT NULL,
            process_name TEXT NOT NULL,
            executable_path TEXT,
            command_line TEXT,
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT NOT NULL,
            is_suspicious INTEGER DEFAULT 0,
            PRIMARY KEY (pid, process_name)
          );

          -- Windows Defender detections & security intelligence
          CREATE TABLE IF NOT EXISTS defender_detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            threat_id TEXT,
            threat_name TEXT NOT NULL,
            severity TEXT,
            resources TEXT,
            action_taken TEXT
          );

          -- Firewall rules created by My Laptop Guard
          CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            rule_name TEXT UNIQUE NOT NULL,
            remote_ip TEXT NOT NULL,
            direction TEXT NOT NULL,
            protocol TEXT DEFAULT 'ANY',
            rule_command TEXT NOT NULL,
            comment TEXT,
            status TEXT DEFAULT 'active',
            created_by TEXT DEFAULT 'user',
            removed_at TEXT
          );

          -- Audit events
          CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            message TEXT NOT NULL,
            details_json TEXT
          );

          -- Collector health & diagnostic telemetry
          CREATE TABLE IF NOT EXISTS system_health (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            collector TEXT NOT NULL,
            status TEXT NOT NULL,
            duration_ms INTEGER,
            message TEXT
          );

          -- Persistence items
          CREATE TABLE IF NOT EXISTS persistence_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            item_type TEXT NOT NULL,
            name TEXT NOT NULL,
            command TEXT,
            location TEXT,
            is_suspicious INTEGER DEFAULT 0,
            UNIQUE(item_type, name, location)
          );

          -- Indexes
          CREATE INDEX IF NOT EXISTS idx_conn_time ON connections_history(timestamp_utc);
          CREATE INDEX IF NOT EXISTS idx_conn_remote ON connections_history(remote_ip);
          CREATE INDEX IF NOT EXISTS idx_conn_pid ON connections_history(pid);
          CREATE INDEX IF NOT EXISTS idx_findings_time ON findings(timestamp_utc);
          CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
          CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
          CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_events(timestamp_utc);
          CREATE INDEX IF NOT EXISTS idx_health_time ON system_health(timestamp_utc);

          INSERT INTO schema_migrations (version, applied_at, description)
          VALUES (1, datetime('now'), 'Baseline schema: connections, findings, processes, defender, firewall, audit, persistence');
        `);
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw new Error(`Migration 1 failed: ${err.message}`);
      }
    }

    // Migration 2: Event Bookmarks, Remote Sessions, Incidents, Posture Snapshots, Trust Allowlist, Monitoring Gaps
    if (!appliedVersions.has(2)) {
      this.db.exec('BEGIN TRANSACTION');
      try {
        this.db.exec(`
          -- Event log bookmarks for persistent tailing without duplicate/missed records
          CREATE TABLE IF NOT EXISTS event_bookmarks (
            channel TEXT PRIMARY KEY,
            last_record_id INTEGER NOT NULL,
            updated_at TEXT NOT NULL
          );

          -- Active and historical remote sessions
          CREATE TABLE IF NOT EXISTS remote_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            username TEXT,
            domain TEXT,
            logon_type INTEGER,
            client_name TEXT,
            client_ip TEXT,
            state TEXT,
            logon_time_utc TEXT,
            tool_name TEXT,
            first_seen_utc TEXT NOT NULL,
            last_seen_utc TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            details_json TEXT
          );

          -- Security Incidents (correlated multi-signal events)
          CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'OPEN',
            summary TEXT,
            primary_ip TEXT,
            primary_process TEXT,
            timeline_json TEXT,
            containment_status TEXT DEFAULT 'UNCONTAINED',
            notes TEXT
          );

          -- Security Posture Snapshots (0-100 score history)
          CREATE TABLE IF NOT EXISTS posture_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            score INTEGER NOT NULL,
            grade TEXT NOT NULL,
            deductions_json TEXT,
            checks_json TEXT
          );

          -- User Trust / Allowlist (scoped by signer, path+hash, or IP)
          CREATE TABLE IF NOT EXISTS trusted_allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_type TEXT NOT NULL,
            target_value TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            expires_at_utc TEXT,
            created_by TEXT DEFAULT 'user'
          );

          -- Monitoring Gaps (tracks sleep, hibernation, reboot, downtime)
          CREATE TABLE IF NOT EXISTS monitoring_gaps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            gap_start_utc TEXT NOT NULL,
            gap_end_utc TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL,
            reason TEXT NOT NULL
          );

          -- Indexes for Migration 2 tables
          CREATE INDEX IF NOT EXISTS idx_remote_sessions_active ON remote_sessions(active);
          CREATE INDEX IF NOT EXISTS idx_remote_sessions_ip ON remote_sessions(client_ip);
          CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
          CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at_utc);
          CREATE INDEX IF NOT EXISTS idx_posture_time ON posture_snapshots(timestamp_utc);
          CREATE INDEX IF NOT EXISTS idx_trust_type ON trusted_allowlist(target_type, target_value);
          CREATE INDEX IF NOT EXISTS idx_gaps_start ON monitoring_gaps(gap_start_utc);

          INSERT INTO schema_migrations (version, applied_at, description)
          VALUES (2, datetime('now'), 'Event bookmarks, remote sessions, incidents, posture snapshots, trust allowlist, monitoring gaps');
        `);
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw new Error(`Migration 2 failed: ${err.message}`);
      }
    }

    // Migration 3: Malware Analysis Reports and Suspicious Outbound Profiles
    if (!appliedVersions.has(3)) {
      this.db.exec('BEGIN TRANSACTION');
      try {
        this.db.exec(`
          -- Local static malware analysis reports
          CREATE TABLE IF NOT EXISTS malware_analysis_reports (
            id TEXT PRIMARY KEY,
            analyzed_at_utc TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            sha1 TEXT NOT NULL,
            md5 TEXT NOT NULL,
            file_type TEXT,
            mime_type TEXT,
            is_pe INTEGER DEFAULT 0,
            signature_status TEXT,
            capabilities_json TEXT,
            iocs_json TEXT,
            report_integrity_hash TEXT NOT NULL,
            report_json TEXT NOT NULL,
            report_html TEXT NOT NULL
          );

          -- Suspicious Outbound / Reverse-Shell Profiles (Section 16.1a)
          CREATE TABLE IF NOT EXISTS suspicious_outbound_profiles (
            id TEXT PRIMARY KEY,
            first_observed_utc TEXT NOT NULL,
            last_observed_utc TEXT NOT NULL,
            pid INTEGER NOT NULL,
            process_name TEXT NOT NULL,
            process_path TEXT,
            command_line TEXT,
            parent_process TEXT,
            peer_ip TEXT NOT NULL,
            peer_port INTEGER NOT NULL,
            has_dns INTEGER DEFAULT 0,
            dns_name TEXT,
            is_common_shell_port INTEGER DEFAULT 0,
            is_beacon INTEGER DEFAULT 0,
            beacon_interval_sec REAL,
            beacon_jitter_percent REAL,
            confidence TEXT NOT NULL,
            plain_english TEXT NOT NULL,
            evidence_json TEXT,
            status TEXT DEFAULT 'ACTIVE'
          );

          -- Indexes for Migration 3
          CREATE INDEX IF NOT EXISTS idx_malware_sha ON malware_analysis_reports(sha256);
          CREATE INDEX IF NOT EXISTS idx_malware_time ON malware_analysis_reports(analyzed_at_utc);
          CREATE INDEX IF NOT EXISTS idx_outbound_peer ON suspicious_outbound_profiles(peer_ip);
          CREATE INDEX IF NOT EXISTS idx_outbound_pid ON suspicious_outbound_profiles(pid);
          CREATE INDEX IF NOT EXISTS idx_outbound_time ON suspicious_outbound_profiles(last_observed_utc);

          INSERT INTO schema_migrations (version, applied_at, description)
          VALUES (3, datetime('now'), 'Local malware analysis reports and suspicious outbound profiles');
        `);
        this.db.exec('COMMIT');
      } catch (err) {
        this.db.exec('ROLLBACK');
        throw new Error(`Migration 3 failed: ${err.message}`);
      }
    }
  }

  /**
   * Records batch of connections in a single transaction.
   * To prevent high disk I/O on 3s intervals, only records new, external, or flagged connections.
   */
  recordConnectionsBatch(connections) {
    if (!this.initialized || !connections || connections.length === 0) return 0;

    const stmt = this.db.prepare(`
      INSERT INTO connections_history (
        timestamp_utc, protocol, local_ip, local_port, remote_ip, remote_port,
        state, pid, process_name, process_path, direction, risk_level, is_external, details_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    let inserted = 0;
    this.db.exec('BEGIN TRANSACTION');
    try {
      for (const conn of connections) {
        stmt.run(
          conn.timestampUtc || new Date().toISOString(),
          conn.protocol || 'TCP',
          conn.localIp || '',
          conn.localPort || 0,
          conn.remoteIp || '',
          conn.remotePort || 0,
          conn.state || '',
          conn.pid || 0,
          conn.processName || '',
          conn.processPath || '',
          conn.direction || 'UNKNOWN',
          conn.riskLevel || 'LOW',
          conn.isExternal ? 1 : 0,
          conn.details ? JSON.stringify(conn.details) : null
        );
        inserted++;
      }
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      console.error('[Database] Failed to batch insert connections:', err.message);
    }
    return inserted;
  }

  /**
   * Retrieves connection history with filtering
   */
  getConnectionHistory(options = {}) {
    const limit = Math.min(Math.max(parseInt(options.limit, 10) || 100, 1), 500);
    const filter = options.filter || '';
    const state = options.state || '';
    const direction = options.direction || '';

    let sql = 'SELECT * FROM connections_history WHERE 1=1';
    const params = [];

    if (filter) {
      sql += ' AND (remote_ip LIKE ? OR process_name LIKE ? OR local_port = ? OR remote_port = ?)';
      params.push(`%${filter}%`, `%${filter}%`, parseInt(filter, 10) || 0, parseInt(filter, 10) || 0);
    }
    if (state) {
      sql += ' AND state = ?';
      params.push(state);
    }
    if (direction) {
      sql += ' AND direction = ?';
      params.push(direction);
    }

    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(sql);
    return stmt.all(...params);
  }

  /**
   * Records or updates a security finding with duplicate suppression
   */
  recordFinding(finding) {
    if (!this.initialized || !finding) return null;

    const timestamp = finding.timestampUtc || new Date().toISOString();
    const fingerprint = finding.fingerprint || `${finding.ruleId}_${finding.pid}_${finding.remoteIp}_${finding.title}`;

    const stmt = this.db.prepare(`
      INSERT INTO findings (
        timestamp_utc, fingerprint, rule_id, title, severity, confidence,
        process_name, pid, remote_ip, explanation, evidence_json, remediation, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(fingerprint) DO UPDATE SET
        timestamp_utc = excluded.timestamp_utc,
        explanation = excluded.explanation,
        evidence_json = excluded.evidence_json
    `);

    stmt.run(
      timestamp,
      fingerprint,
      finding.ruleId || 'RULE_UNKNOWN',
      finding.title || 'Suspicious Activity Detected',
      finding.severity || 'MEDIUM',
      finding.confidence || 'MEDIUM',
      finding.processName || null,
      finding.pid || null,
      finding.remoteIp || null,
      finding.explanation || '',
      finding.evidence ? JSON.stringify(finding.evidence) : null,
      finding.remediation || '',
      finding.status || 'active'
    );

    return this.db.prepare('SELECT * FROM findings WHERE fingerprint = ?').get(fingerprint);
  }

  /**
   * Retrieves findings with optional status filter
   */
  getFindings(options = {}) {
    const limit = Math.min(Math.max(parseInt(options.limit, 10) || 100, 1), 300);
    const status = options.status || '';
    const severity = options.severity || '';

    let sql = 'SELECT * FROM findings WHERE 1=1';
    const params = [];

    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }
    if (severity) {
      sql += ' AND severity = ?';
      params.push(severity);
    }

    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params);
    return rows.map(r => ({
      ...r,
      evidence: r.evidence_json ? JSON.parse(r.evidence_json) : []
    }));
  }

  /**
   * Resolves or acknowledges a finding
   */
  resolveFinding(id, notes = 'Acknowledged by user') {
    const stmt = this.db.prepare(`
      UPDATE findings
      SET status = 'resolved', resolved_at = ?, resolved_notes = ?
      WHERE id = ?
    `);
    stmt.run(new Date().toISOString(), notes, id);
    return this.db.prepare('SELECT * FROM findings WHERE id = ?').get(id);
  }

  /**
   * Records or updates known process details
   */
  upsertProcess(proc) {
    if (!this.initialized || !proc || !proc.pid) return;

    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      INSERT INTO processes (
        pid, process_name, executable_path, command_line, first_seen_utc, last_seen_utc, is_suspicious
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(pid, process_name) DO UPDATE SET
        executable_path = COALESCE(excluded.executable_path, processes.executable_path),
        command_line = COALESCE(excluded.command_line, processes.command_line),
        last_seen_utc = excluded.last_seen_utc,
        is_suspicious = excluded.is_suspicious
    `);

    const cleanCmd = proc.commandLine ? redactSensitiveData(proc.commandLine) : null;
    stmt.run(
      proc.pid,
      proc.processName || 'Unknown',
      proc.executablePath || null,
      cleanCmd,
      proc.firstSeenUtc || now,
      now,
      proc.isSuspicious ? 1 : 0
    );
  }

  /**
   * Retrieves catalogue of known processes
   */
  getProcesses(options = {}) {
    if (!this.initialized) return [];
    const limit = Math.min(Math.max(parseInt(options.limit, 10) || 300, 1), 2000);
    const filter = options.filter ? `%${options.filter.toLowerCase()}%` : null;

    let sql = 'SELECT * FROM processes';
    const params = [];
    if (filter) {
      sql += ' WHERE LOWER(process_name) LIKE ? OR LOWER(executable_path) LIKE ?';
      params.push(filter, filter);
    }
    sql += ' ORDER BY last_seen_utc DESC LIMIT ?';
    params.push(limit);

    return this.db.prepare(sql).all(...params);
  }

  getProcess(pid) {
    if (!this.initialized || !pid) return null;
    return this.db.prepare('SELECT * FROM processes WHERE pid = ? ORDER BY last_seen_utc DESC LIMIT 1').get(pid);
  }

  /**
   * Records Windows Defender detections
   */
  recordDefenderDetection(threat) {
    if (!this.initialized || !threat) return;

    const stmt = this.db.prepare(`
      INSERT INTO defender_detections (
        timestamp_utc, threat_id, threat_name, severity, resources, action_taken
      ) VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      threat.timestampUtc || new Date().toISOString(),
      threat.threatId ? String(threat.threatId) : null,
      threat.threatName || 'Unknown Threat',
      threat.severity || 'Unknown',
      threat.resources || '',
      threat.actionTaken || 'Detected'
    );
  }

  getDefenderDetections(limit = 50) {
    if (!this.initialized) return [];
    const stmt = this.db.prepare('SELECT * FROM defender_detections ORDER BY id DESC LIMIT ?');
    return stmt.all(limit);
  }

  /**
   * Records a created Windows Firewall rule
   */
  recordFirewallRule(rule) {
    if (!this.initialized || !rule) return;

    const stmt = this.db.prepare(`
      INSERT INTO firewall_rules (
        timestamp_utc, rule_name, remote_ip, direction, protocol, rule_command, comment, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?)
    `);

    stmt.run(
      rule.timestampUtc || new Date().toISOString(),
      rule.ruleName,
      rule.remoteIp,
      rule.direction || 'OUT',
      rule.protocol || 'ANY',
      rule.ruleCommand,
      rule.comment || '',
      rule.createdBy || 'user'
    );
  }

  getFirewallRules() {
    if (!this.initialized) return [];
    const stmt = this.db.prepare('SELECT * FROM firewall_rules ORDER BY id DESC');
    return stmt.all();
  }

  markFirewallRuleRemoved(ruleName) {
    if (!this.initialized) return;
    const stmt = this.db.prepare(`
      UPDATE firewall_rules
      SET status = 'removed', removed_at = ?
      WHERE rule_name = ?
    `);
    stmt.run(new Date().toISOString(), ruleName);
  }

  /**
   * Records an audit event for administrative or security actions
   */
  recordAuditEvent(eventType, actor, message, details = null) {
    if (!this.initialized) return;

    const stmt = this.db.prepare(`
      INSERT INTO audit_events (timestamp_utc, event_type, actor, message, details_json)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      new Date().toISOString(),
      eventType,
      actor || 'SYSTEM',
      message,
      details ? JSON.stringify(details) : null
    );
  }

  getAuditEvents(limit = 100) {
    if (!this.initialized) return [];
    const stmt = this.db.prepare('SELECT * FROM audit_events ORDER BY id DESC LIMIT ?');
    const rows = stmt.all(limit);
    return rows.map(r => ({
      ...r,
      details: r.details_json ? JSON.parse(r.details_json) : null
    }));
  }

  /**
   * Records collector health metrics
   */
  recordHealth(collector, status, durationMs = 0, message = '') {
    if (!this.initialized) return;

    const stmt = this.db.prepare(`
      INSERT INTO system_health (timestamp_utc, collector, status, duration_ms, message)
      VALUES (?, ?, ?, ?, ?)
    `);

    stmt.run(
      new Date().toISOString(),
      collector,
      status,
      durationMs,
      message
    );
  }

  getLatestHealth() {
    if (!this.initialized) return [];
    const stmt = this.db.prepare(`
      SELECT * FROM system_health
      WHERE id IN (SELECT MAX(id) FROM system_health GROUP BY collector)
      ORDER BY id DESC
    `);
    return stmt.all();
  }

  /**
   * Persistence item upsert (Startup apps, tasks)
   */
  syncPersistenceItems(items) {
    if (!this.initialized || !items || items.length === 0) return;

    const stmt = this.db.prepare(`
      INSERT INTO persistence_items (timestamp_utc, item_type, name, command, location, is_suspicious)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(item_type, name, location) DO UPDATE SET
        timestamp_utc = excluded.timestamp_utc,
        command = excluded.command,
        is_suspicious = excluded.is_suspicious
    `);

    const now = new Date().toISOString();
    this.db.exec('BEGIN TRANSACTION');
    try {
      for (const it of items) {
        const cleanCmd = it.command ? redactSensitiveData(it.command) : '';
        stmt.run(
          now,
          it.itemType || 'StartupCommand',
          it.name || 'Unnamed',
          cleanCmd,
          it.location || '',
          it.isSuspicious ? 1 : 0
        );
      }
      this.db.exec('COMMIT');
    } catch (e) {
      this.db.exec('ROLLBACK');
      console.error('[Database] Failed to sync persistence items:', e.message);
    }
  }

  getPersistenceItems() {
    if (!this.initialized) return [];
    const stmt = this.db.prepare('SELECT * FROM persistence_items ORDER BY is_suspicious DESC, name ASC');
    return stmt.all();
  }

  deletePersistenceItem(name, location) {
    if (!this.initialized) return;
    const stmt = this.db.prepare('DELETE FROM persistence_items WHERE name = ? AND location = ?');
    stmt.run(name, location);
  }

  /**
   * Event Log Bookmarks for persistent event tailing
   */
  getBookmark(channel) {
    if (!this.initialized || !channel) return 0;
    const row = this.db.prepare('SELECT last_record_id FROM event_bookmarks WHERE channel = ?').get(channel);
    return row ? row.last_record_id : 0;
  }

  setBookmark(channel, recordId) {
    if (!this.initialized || !channel) return;
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO event_bookmarks (channel, last_record_id, updated_at)
      VALUES (?, ?, ?)
      ON CONFLICT(channel) DO UPDATE SET
        last_record_id = excluded.last_record_id,
        updated_at = excluded.updated_at
    `).run(channel, recordId, now);
  }

  /**
   * Remote Sessions tracking (live and historical)
   */
  upsertRemoteSession(session) {
    if (!this.initialized || !session || !session.sessionId) return;
    const now = new Date().toISOString();
    const existing = this.db.prepare(
      'SELECT id, first_seen_utc FROM remote_sessions WHERE session_id = ? AND active = 1 ORDER BY id DESC LIMIT 1'
    ).get(session.sessionId);

    if (existing) {
      this.db.prepare(`
        UPDATE remote_sessions
        SET username = COALESCE(?, username),
            domain = COALESCE(?, domain),
            client_name = COALESCE(?, client_name),
            client_ip = COALESCE(?, client_ip),
            state = COALESCE(?, state),
            tool_name = COALESCE(?, tool_name),
            last_seen_utc = ?,
            details_json = ?
        WHERE id = ?
      `).run(
        session.username || null,
        session.domain || null,
        session.clientName || null,
        session.clientIp || null,
        session.state || null,
        session.toolName || null,
        now,
        session.details ? JSON.stringify(session.details) : null,
        existing.id
      );
    } else {
      this.db.prepare(`
        INSERT INTO remote_sessions (
          session_id, username, domain, logon_type, client_name, client_ip,
          state, logon_time_utc, tool_name, first_seen_utc, last_seen_utc, active, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
      `).run(
        session.sessionId,
        session.username || 'Unknown',
        session.domain || '',
        session.logonType || null,
        session.clientName || '',
        session.clientIp || '',
        session.state || 'Active',
        session.logonTimeUtc || now,
        session.toolName || 'RDP/TerminalServices',
        now,
        now,
        session.details ? JSON.stringify(session.details) : null
      );
    }
  }

  getActiveRemoteSessions() {
    if (!this.initialized) return [];
    const rows = this.db.prepare('SELECT * FROM remote_sessions WHERE active = 1 ORDER BY id DESC').all();
    return rows.map(r => ({
      ...r,
      details: r.details_json ? JSON.parse(r.details_json) : null
    }));
  }

  closeRemoteSession(sessionId) {
    if (!this.initialized) return;
    const now = new Date().toISOString();
    this.db.prepare(`
      UPDATE remote_sessions
      SET active = 0, state = 'Disconnected', last_seen_utc = ?
      WHERE session_id = ? AND active = 1
    `).run(now, sessionId);
  }

  getRemoteSessionHistory(limit = 100) {
    if (!this.initialized) return [];
    const rows = this.db.prepare('SELECT * FROM remote_sessions ORDER BY id DESC LIMIT ?').all(limit);
    return rows.map(r => ({
      ...r,
      details: r.details_json ? JSON.parse(r.details_json) : null
    }));
  }

  /**
   * Correlated Security Incidents
   */
  recordIncident(incident) {
    if (!this.initialized || !incident || !incident.id) return;
    const now = new Date().toISOString();
    const stmt = this.db.prepare(`
      INSERT INTO incidents (
        id, created_at_utc, updated_at_utc, title, severity, status,
        summary, primary_ip, primary_process, timeline_json, containment_status, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        updated_at_utc = excluded.updated_at_utc,
        title = excluded.title,
        severity = excluded.severity,
        status = excluded.status,
        summary = excluded.summary,
        primary_ip = excluded.primary_ip,
        primary_process = excluded.primary_process,
        timeline_json = excluded.timeline_json,
        containment_status = excluded.containment_status,
        notes = excluded.notes
    `);

    stmt.run(
      incident.id,
      incident.createdAtUtc || now,
      now,
      incident.title || 'Security Incident',
      incident.severity || 'HIGH',
      incident.status || 'OPEN',
      incident.summary || '',
      incident.primaryIp || null,
      incident.primaryProcess || null,
      incident.timeline ? JSON.stringify(incident.timeline) : '[]',
      incident.containmentStatus || 'UNCONTAINED',
      incident.notes || ''
    );
  }

  getIncidents(options = {}) {
    if (!this.initialized) return [];
    const limit = Math.min(Math.max(parseInt(options.limit, 10) || 50, 1), 200);
    const status = options.status || '';
    let sql = 'SELECT * FROM incidents WHERE 1=1';
    const params = [];
    if (status) {
      sql += ' AND status = ?';
      params.push(status);
    }
    sql += ' ORDER BY created_at_utc DESC LIMIT ?';
    params.push(limit);

    const rows = this.db.prepare(sql).all(...params);
    return rows.map(r => ({
      ...r,
      timeline: r.timeline_json ? JSON.parse(r.timeline_json) : []
    }));
  }

  getIncidentById(id) {
    if (!this.initialized || !id) return null;
    const r = this.db.prepare('SELECT * FROM incidents WHERE id = ?').get(id);
    if (!r) return null;
    return {
      ...r,
      timeline: r.timeline_json ? JSON.parse(r.timeline_json) : []
    };
  }

  updateIncident(id, updates = {}) {
    if (!this.initialized || !id) return;
    const now = new Date().toISOString();
    const current = this.getIncidentById(id);
    if (!current) return;

    this.db.prepare(`
      UPDATE incidents
      SET updated_at_utc = ?,
          status = COALESCE(?, status),
          containment_status = COALESCE(?, containment_status),
          notes = COALESCE(?, notes),
          timeline_json = COALESCE(?, timeline_json)
      WHERE id = ?
    `).run(
      now,
      updates.status || null,
      updates.containmentStatus || null,
      updates.notes || null,
      updates.timeline ? JSON.stringify(updates.timeline) : null,
      id
    );
  }

  /**
   * Posture Snapshots (0-100 score tracking)
   */
  recordPostureSnapshot(snap) {
    if (!this.initialized || !snap) return;
    const stmt = this.db.prepare(`
      INSERT INTO posture_snapshots (timestamp_utc, score, grade, deductions_json, checks_json)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(
      snap.timestampUtc || new Date().toISOString(),
      snap.score !== undefined ? snap.score : 0,
      snap.grade || 'F',
      snap.deductions ? JSON.stringify(snap.deductions) : '[]',
      snap.checks ? JSON.stringify(snap.checks) : '{}'
    );
  }

  getLatestPostureSnapshot() {
    if (!this.initialized) return null;
    const row = this.db.prepare('SELECT * FROM posture_snapshots ORDER BY id DESC LIMIT 1').get();
    if (!row) return null;
    return {
      ...row,
      deductions: row.deductions_json ? JSON.parse(row.deductions_json) : [],
      checks: row.checks_json ? JSON.parse(row.checks_json) : {}
    };
  }

  getPostureHistory(limit = 30) {
    if (!this.initialized) return [];
    const rows = this.db.prepare('SELECT * FROM posture_snapshots ORDER BY id DESC LIMIT ?').all(limit);
    return rows.map(r => ({
      ...r,
      deductions: r.deductions_json ? JSON.parse(r.deductions_json) : [],
      checks: r.checks_json ? JSON.parse(r.checks_json) : {}
    }));
  }

  /**
   * User Trust / Allowlist
   */
  addTrustEntry({ targetType, targetValue, reason, expiresAtUtc, createdBy }) {
    if (!this.initialized || !targetType || !targetValue) return;
    const stmt = this.db.prepare(`
      INSERT INTO trusted_allowlist (target_type, target_value, reason, created_at_utc, expires_at_utc, created_by)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      targetType.toUpperCase(),
      targetValue.trim(),
      reason || 'User authorized',
      new Date().toISOString(),
      expiresAtUtc || null,
      createdBy || 'user'
    );
  }

  getTrustList() {
    if (!this.initialized) return [];
    return this.db.prepare('SELECT * FROM trusted_allowlist ORDER BY id DESC').all();
  }

  isTrusted(targetType, targetValue) {
    if (!this.initialized || !targetType || !targetValue) return false;
    const now = new Date().toISOString();
    const row = this.db.prepare(`
      SELECT id FROM trusted_allowlist
      WHERE target_type = ? AND LOWER(target_value) = LOWER(?)
        AND (expires_at_utc IS NULL OR expires_at_utc > ?)
      LIMIT 1
    `).get(targetType.toUpperCase(), targetValue.trim(), now);
    return !!row;
  }

  removeTrustEntry(id) {
    if (!this.initialized || !id) return;
    this.db.prepare('DELETE FROM trusted_allowlist WHERE id = ?').run(id);
  }

  /**
   * Monitoring Gaps (Sleep, hibernate, downtime detection)
   */
  recordMonitoringGap(startUtc, endUtc, durationSec, reason = 'System sleep or service restart') {
    if (!this.initialized) return;
    this.db.prepare(`
      INSERT INTO monitoring_gaps (gap_start_utc, gap_end_utc, duration_seconds, reason)
      VALUES (?, ?, ?, ?)
    `).run(startUtc, endUtc, durationSec, reason);
  }

  /**
   * Malware Analysis Reports (Static Analysis)
   */
  saveMalwareReport(report) {
    if (!this.initialized || !report || !report.id) return;
    const stmt = this.db.prepare(`
      INSERT INTO malware_analysis_reports (
        id, analyzed_at_utc, file_path, file_name, file_size,
        sha256, sha1, md5, file_type, mime_type, is_pe,
        signature_status, capabilities_json, iocs_json,
        report_integrity_hash, report_json, report_html
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        analyzed_at_utc = excluded.analyzed_at_utc,
        report_integrity_hash = excluded.report_integrity_hash,
        report_json = excluded.report_json,
        report_html = excluded.report_html
    `);

    stmt.run(
      report.id,
      report.analyzedAtUtc || new Date().toISOString(),
      report.filePath || '',
      report.fileName || '',
      report.fileSize || 0,
      report.hashes ? report.hashes.sha256 : (report.sha256 || ''),
      report.hashes ? report.hashes.sha1 : (report.sha1 || ''),
      report.hashes ? report.hashes.md5 : (report.md5 || ''),
      report.fileType || 'Unknown',
      report.mimeType || 'application/octet-stream',
      report.isPe ? 1 : 0,
      report.signatureStatus || 'Unsigned',
      report.capabilities ? JSON.stringify(report.capabilities) : '[]',
      report.iocs ? JSON.stringify(report.iocs) : '[]',
      report.integrityHash || report.reportIntegrityHash || '',
      report.reportJson || (typeof report === 'object' ? JSON.stringify(report) : '{}'),
      report.reportHtml || ''
    );
  }

  getMalwareReports(limit = 50) {
    if (!this.initialized) return [];
    const rows = this.db.prepare(`
      SELECT id, analyzed_at_utc, file_path, file_name, file_size,
             sha256, sha1, md5, file_type, is_pe, signature_status,
             capabilities_json, iocs_json, report_integrity_hash
      FROM malware_analysis_reports
      ORDER BY analyzed_at_utc DESC
      LIMIT ?
    `).all(limit);

    return rows.map(r => ({
      ...r,
      capabilities: r.capabilities_json ? JSON.parse(r.capabilities_json) : [],
      iocs: r.iocs_json ? JSON.parse(r.iocs_json) : []
    }));
  }

  getMalwareReport(id) {
    if (!this.initialized || !id) return null;
    const row = this.db.prepare('SELECT * FROM malware_analysis_reports WHERE id = ?').get(id);
    if (!row) return null;
    return {
      ...row,
      capabilities: row.capabilities_json ? JSON.parse(row.capabilities_json) : [],
      iocs: row.iocs_json ? JSON.parse(row.iocs_json) : [],
      report: row.report_json ? JSON.parse(row.report_json) : null
    };
  }

  /**
   * Suspicious Outbound Profiles (Section 16.1a)
   */
  upsertSuspiciousOutbound(profile) {
    if (!this.initialized || !profile || !profile.id) return;
    const stmt = this.db.prepare(`
      INSERT INTO suspicious_outbound_profiles (
        id, first_observed_utc, last_observed_utc, pid, process_name,
        process_path, command_line, parent_process, peer_ip, peer_port,
        has_dns, dns_name, is_common_shell_port, is_beacon,
        beacon_interval_sec, beacon_jitter_percent, confidence,
        plain_english, evidence_json, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        last_observed_utc = excluded.last_observed_utc,
        beacon_interval_sec = excluded.beacon_interval_sec,
        beacon_jitter_percent = excluded.beacon_jitter_percent,
        confidence = excluded.confidence,
        plain_english = excluded.plain_english,
        evidence_json = excluded.evidence_json,
        status = excluded.status
    `);

    const cmd = profile.commandLine || profile.command_line || '';
    const interval = profile.beaconIntervalSec !== undefined ? profile.beaconIntervalSec : (profile.beacon_interval_sec !== undefined ? profile.beacon_interval_sec : null);
    const jitter = profile.beaconJitterPercent !== undefined ? profile.beaconJitterPercent : (profile.beacon_jitter_percent !== undefined ? profile.beacon_jitter_percent : null);

    stmt.run(
      profile.id,
      profile.firstObservedUtc || profile.first_observed_utc || new Date().toISOString(),
      profile.lastObservedUtc || profile.last_observed_utc || new Date().toISOString(),
      profile.pid || 0,
      profile.processName || profile.process_name || '',
      profile.processPath || profile.process_path || '',
      cmd ? redactSensitiveData(cmd) : '',
      profile.parentProcess || profile.parentProcessName || profile.parent_process || '',
      profile.peerIp || profile.remoteIp || profile.peer_ip || '',
      profile.peerPort || profile.remotePort || profile.peer_port || 0,
      (profile.hasDns !== undefined ? profile.hasDns : profile.has_dns) ? 1 : 0,
      profile.dnsName || profile.dns_name || '',
      (profile.isCommonShellPort !== undefined ? profile.isCommonShellPort : profile.is_common_shell_port) ? 1 : 0,
      (profile.isBeacon !== undefined ? profile.isBeacon : profile.is_beacon) ? 1 : 0,
      interval,
      jitter,
      profile.confidence || 'MEDIUM',
      profile.plainEnglish || profile.summary || profile.plain_english || '',
      profile.evidence ? JSON.stringify(profile.evidence) : (profile.evidence_json || '[]'),
      profile.status || 'ACTIVE'
    );
  }

  getSuspiciousOutboundProfiles(limit = 50) {
    if (!this.initialized) return [];
    const rows = this.db.prepare(`
      SELECT * FROM suspicious_outbound_profiles
      ORDER BY last_observed_utc DESC
      LIMIT ?
    `).all(limit);

    return rows.map(r => {
      let evidence = [];
      try {
        evidence = r.evidence_json ? JSON.parse(r.evidence_json) : [];
      } catch (e) {
        evidence = [];
      }

      return {
        ...r,
        // Normalized camelCase properties
        id: r.id,
        pid: r.pid,
        processName: r.process_name,
        processPath: r.process_path,
        commandLine: r.command_line,
        parentProcess: r.parent_process,
        parentProcessName: r.parent_process,
        peerIp: r.peer_ip,
        peerPort: r.peer_port,
        remoteIp: r.peer_ip,
        remotePort: r.peer_port,
        hasDns: Boolean(r.has_dns),
        dnsName: r.dns_name,
        isCommonShellPort: Boolean(r.is_common_shell_port),
        isBeacon: Boolean(r.is_beacon),
        beaconIntervalSec: r.beacon_interval_sec,
        beaconJitterPercent: r.beacon_jitter_percent,
        confidence: r.confidence,
        plainEnglish: r.plain_english,
        summary: r.plain_english,
        evidence: evidence,
        status: r.status,
        firstObservedUtc: r.first_observed_utc,
        lastObservedUtc: r.last_observed_utc,
        beaconMetrics: r.beacon_interval_sec !== null ? {
          isBeaconLike: Boolean(r.is_beacon),
          meanIntervalSeconds: r.beacon_interval_sec,
          jitterPercent: r.beacon_jitter_percent
        } : null
      };
    });
  }

  /**
   * Prunes records older than retentionDays or caps table rows to avoid unbounded DB growth
   */
  pruneOldRecords(retentionDays = 7) {
    if (!this.initialized) return { connectionsPruned: 0, healthPruned: 0 };

    const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();

    const connStmt = this.db.prepare('DELETE FROM connections_history WHERE timestamp_utc < ?');
    const healthStmt = this.db.prepare('DELETE FROM system_health WHERE timestamp_utc < ?');
    const auditStmt = this.db.prepare('DELETE FROM audit_events WHERE timestamp_utc < ?');

    connStmt.run(cutoff);
    healthStmt.run(cutoff);
    auditStmt.run(cutoff);

    // Run incremental VACUUM or WAL checkpoint if needed
    try {
      this.db.exec('PRAGMA wal_checkpoint(PASSIVE);');
    } catch (e) {
      // Non-critical
    }

    return { prunedBefore: cutoff };
  }

  /**
   * High-performance dashboard summary in single roundtrip
   */
  getDashboardSummary() {
    if (!this.initialized) return {};

    const activeFindings = this.db.prepare("SELECT COUNT(*) AS count FROM findings WHERE status = 'active'").get();
    const criticalFindings = this.db.prepare("SELECT COUNT(*) AS count FROM findings WHERE status = 'active' AND severity = 'CRITICAL'").get();
    const totalRules = this.db.prepare("SELECT COUNT(*) AS count FROM firewall_rules WHERE status = 'active'").get();
    const recentConnectionsCount = this.db.prepare('SELECT COUNT(*) AS count FROM connections_history').get();

    return {
      activeFindingsCount: activeFindings ? activeFindings.count : 0,
      criticalFindingsCount: criticalFindings ? criticalFindings.count : 0,
      activeFirewallRulesCount: totalRules ? totalRules.count : 0,
      totalHistoricalConnections: recentConnectionsCount ? recentConnectionsCount.count : 0,
      latestHealth: this.getLatestHealth()
    };
  }

  close() {
    if (this.db) {
      this.db.close();
      this.initialized = false;
    }
  }
}

// Export singleton instance with easy test factory
const dbInstance = new GuardDatabase();
module.exports = dbInstance;
module.exports.GuardDatabase = GuardDatabase;
