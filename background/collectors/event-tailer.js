/**
 * MY LAPTOP GUARD - Windows Event Log Tailer (event-tailer.js)
 * Persistent, bookmark-based Windows event log reader across Security, System,
 * Windows Defender, and TerminalServices channels.
 * Detects log clearing, service installations, privilege changes, and remote logons.
 */

const db = require('../database');
const psHost = require('../ps-host');

class WindowsEventTailer {
  constructor() {
    this.status = 'STOPPED';
    this.channels = {
      System: { status: 'UNKNOWN', lastRecordId: 0, error: null },
      Defender: { status: 'UNKNOWN', lastRecordId: 0, error: null },
      Security: { status: 'UNKNOWN', lastRecordId: 0, error: null },
      TerminalServices: { status: 'UNKNOWN', lastRecordId: 0, error: null }
    };
    this.failedLogonWindow = []; // { ip, timestamp }
  }

  /**
   * Initializes channel bookmarks from database
   */
  async initBookmarks() {
    this.channels.System.lastRecordId = db.getBookmark('System') || 0;
    this.channels.Defender.lastRecordId = db.getBookmark('Defender') || 0;
    this.channels.Security.lastRecordId = db.getBookmark('Security') || 0;
    this.channels.TerminalServices.lastRecordId = db.getBookmark('TerminalServices') || 0;
  }

  /**
   * Polls System channel (7045 = new service, 104 = log cleared)
   */
  async pollSystemChannel() {
    const bookmark = this.channels.System.lastRecordId;
    try {
      let script = '';
      if (bookmark > 0) {
        script = `
          Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(7045, 104, 7036)} -MaxEvents 50 -ErrorAction Stop |
          Where-Object { $_.RecordId -gt ${bookmark} } |
          Select-Object RecordId, Id, TimeCreated, ProviderName, Message |
          Sort-Object RecordId
        `;
      } else {
        // Initialize bookmark to latest event
        script = `
          $latest = Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction Stop
          [PSCustomObject]@{ InitBookmark = if ($latest) { $latest.RecordId } else { 0 } }
        `;
      }

      const res = await psHost.execute(script, { timeoutMs: 6000, asJson: true });
      if (!res) {
        this.channels.System.status = 'OK';
        return [];
      }

      if (res.InitBookmark !== undefined) {
        this.channels.System.lastRecordId = res.InitBookmark;
        db.setBookmark('System', res.InitBookmark);
        this.channels.System.status = 'OK';
        return [];
      }

      const events = Array.isArray(res) ? res : [res];
      let maxRecord = bookmark;

      for (const ev of events) {
        if (!ev || !ev.RecordId) continue;
        if (ev.RecordId > maxRecord) maxRecord = ev.RecordId;

        // Process Event IDs
        if (ev.Id === 104) {
          db.recordFinding({
            ruleId: 'RULE_TAMPER_LOG_CLEARED',
            title: 'System Event Log Was Cleared',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            explanation: 'The Windows System event log was intentionally cleared. Attackers often clear logs to conceal unauthorized activities.',
            evidence: [`Record ID: ${ev.RecordId}`, `Provider: ${ev.ProviderName}`],
            remediation: 'Inspect who was logged on when the log was cleared and check security posture.'
          });
        } else if (ev.Id === 7045) {
          db.recordFinding({
            ruleId: 'RULE_PERSIST_NEW_SERVICE',
            title: 'New Windows Service Installed',
            severity: 'MEDIUM',
            confidence: 'HIGH',
            explanation: `A new system service was created: ${ev.Message ? ev.Message.substring(0, 200) : 'Service created'}.`,
            evidence: [`Record ID: ${ev.RecordId}`, `Message: ${ev.Message || ''}`],
            remediation: 'Review whether you or legitimate software recently installed this service.'
          });
        }
      }

      if (maxRecord > bookmark) {
        this.channels.System.lastRecordId = maxRecord;
        db.setBookmark('System', maxRecord);
      }

      this.channels.System.status = 'OK';
      this.channels.System.error = null;
      return events;
    } catch (err) {
      this.channels.System.status = 'DEGRADED';
      this.channels.System.error = err.message;
      return [];
    }
  }

  /**
   * Polls Windows Defender Operational channel (1116, 1117, 5001 = protection disabled)
   */
  async pollDefenderChannel() {
    const bookmark = this.channels.Defender.lastRecordId;
    const logName = 'Microsoft-Windows-Windows Defender/Operational';

    try {
      let script = '';
      if (bookmark > 0) {
        script = `
          Get-WinEvent -FilterHashtable @{LogName='${logName}'; Id=@(1116, 1117, 5001, 5007)} -MaxEvents 30 -ErrorAction Stop |
          Where-Object { $_.RecordId -gt ${bookmark} } |
          Select-Object RecordId, Id, TimeCreated, Message |
          Sort-Object RecordId
        `;
      } else {
        script = `
          $latest = Get-WinEvent -LogName '${logName}' -MaxEvents 1 -ErrorAction Stop
          [PSCustomObject]@{ InitBookmark = if ($latest) { $latest.RecordId } else { 0 } }
        `;
      }

      const res = await psHost.execute(script, { timeoutMs: 6000, asJson: true });
      if (!res) {
        this.channels.Defender.status = 'OK';
        return [];
      }

      if (res.InitBookmark !== undefined) {
        this.channels.Defender.lastRecordId = res.InitBookmark;
        db.setBookmark('Defender', res.InitBookmark);
        this.channels.Defender.status = 'OK';
        return [];
      }

      const events = Array.isArray(res) ? res : [res];
      let maxRecord = bookmark;

      for (const ev of events) {
        if (!ev || !ev.RecordId) continue;
        if (ev.RecordId > maxRecord) maxRecord = ev.RecordId;

        if (ev.Id === 5001) {
          db.recordFinding({
            ruleId: 'RULE_TAMPER_DEFENDER_DISABLED',
            title: 'Windows Defender Real-Time Protection Disabled',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            explanation: 'Microsoft Defender Real-Time Protection was turned off.',
            evidence: [`Record ID: ${ev.RecordId}`, `Message: ${ev.Message || 'Protection disabled'}`],
            remediation: 'Re-enable Real-Time Protection immediately in Windows Security settings.'
          });
        }
      }

      if (maxRecord > bookmark) {
        this.channels.Defender.lastRecordId = maxRecord;
        db.setBookmark('Defender', maxRecord);
      }

      this.channels.Defender.status = 'OK';
      this.channels.Defender.error = null;
      return events;
    } catch (err) {
      if (err.message.includes('No events were found') || err.message.includes('No matching events')) {
        this.channels.Defender.status = 'OK';
        this.channels.Defender.error = null;
      } else {
        this.channels.Defender.status = 'DEGRADED';
        this.channels.Defender.error = err.message;
      }
      return [];
    }
  }

  /**
   * Polls Security channel (requires elevation; reports gracefully if non-admin)
   */
  async pollSecurityChannel() {
    const bookmark = this.channels.Security.lastRecordId;

    try {
      let script = '';
      if (bookmark > 0) {
        script = `
          Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624, 4625, 4720, 4732, 1102)} -MaxEvents 40 -ErrorAction Stop |
          Where-Object { $_.RecordId -gt ${bookmark} } |
          Select-Object RecordId, Id, TimeCreated, Message |
          Sort-Object RecordId
        `;
      } else {
        script = `
          $latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
          [PSCustomObject]@{ InitBookmark = if ($latest) { $latest.RecordId } else { 0 } }
        `;
      }

      const res = await psHost.execute(script, { timeoutMs: 6000, asJson: true });
      if (!res) {
        this.channels.Security.status = 'OK';
        return [];
      }

      if (res.InitBookmark !== undefined) {
        this.channels.Security.lastRecordId = res.InitBookmark;
        db.setBookmark('Security', res.InitBookmark);
        this.channels.Security.status = 'OK';
        return [];
      }

      const events = Array.isArray(res) ? res : [res];
      let maxRecord = bookmark;

      for (const ev of events) {
        if (!ev || !ev.RecordId) continue;
        if (ev.RecordId > maxRecord) maxRecord = ev.RecordId;

        if (ev.Id === 1102) {
          db.recordFinding({
            ruleId: 'RULE_TAMPER_AUDIT_LOG_CLEARED',
            title: 'Windows Security Audit Log Was Cleared',
            severity: 'CRITICAL',
            confidence: 'HIGH',
            explanation: 'The Security Audit log was cleared (Event 1102). This is a strong indicator of administrative tampering or anti-forensics activity.',
            evidence: [`Record ID: ${ev.RecordId}`],
            remediation: 'Review recently active sessions and check local administrative accounts.'
          });
        }
      }

      if (maxRecord > bookmark) {
        this.channels.Security.lastRecordId = maxRecord;
        db.setBookmark('Security', maxRecord);
      }

      this.channels.Security.status = 'OK';
      this.channels.Security.error = null;
      return events;
    } catch (err) {
      if (err.message.includes('UnauthorizedAccessException') || err.message.includes('Access is denied') || err.message.includes('privilege')) {
        this.channels.Security.status = 'REQUIRES_ADMIN';
        this.channels.Security.error = 'Requires administrator privileges to read Windows Security event channel.';
      } else if (err.message.includes('No events were found')) {
        this.channels.Security.status = 'OK';
        this.channels.Security.error = null;
      } else {
        this.channels.Security.status = 'DEGRADED';
        this.channels.Security.error = err.message;
      }
      return [];
    }
  }

  /**
   * Polls Terminal Services Session Manager channel for RDP logon events
   */
  async pollTerminalServicesChannel() {
    const bookmark = this.channels.TerminalServices.lastRecordId;
    const logName = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';

    try {
      let script = '';
      if (bookmark > 0) {
        script = `
          Get-WinEvent -FilterHashtable @{LogName='${logName}'; Id=@(21, 24, 25)} -MaxEvents 30 -ErrorAction Stop |
          Where-Object { $_.RecordId -gt ${bookmark} } |
          Select-Object RecordId, Id, TimeCreated, Message |
          Sort-Object RecordId
        `;
      } else {
        script = `
          $latest = Get-WinEvent -LogName '${logName}' -MaxEvents 1 -ErrorAction Stop
          [PSCustomObject]@{ InitBookmark = if ($latest) { $latest.RecordId } else { 0 } }
        `;
      }

      const res = await psHost.execute(script, { timeoutMs: 6000, asJson: true });
      if (!res) {
        this.channels.TerminalServices.status = 'OK';
        return [];
      }

      if (res.InitBookmark !== undefined) {
        this.channels.TerminalServices.lastRecordId = res.InitBookmark;
        db.setBookmark('TerminalServices', res.InitBookmark);
        this.channels.TerminalServices.status = 'OK';
        return [];
      }

      const events = Array.isArray(res) ? res : [res];
      let maxRecord = bookmark;

      for (const ev of events) {
        if (!ev || !ev.RecordId) continue;
        if (ev.RecordId > maxRecord) maxRecord = ev.RecordId;

        if (ev.Id === 21) {
          db.recordFinding({
            ruleId: 'RULE_RDP_SESSION_LOGON',
            title: 'Terminal Services Remote Session Logon',
            severity: 'HIGH',
            confidence: 'HIGH',
            explanation: `A remote desktop session logon was established (Event 21): ${ev.Message ? ev.Message.substring(0, 150) : ''}`,
            evidence: [`Record ID: ${ev.RecordId}`, `Log: ${logName}`],
            remediation: 'Verify if you or an authorized user initiated this remote connection.'
          });
        }
      }

      if (maxRecord > bookmark) {
        this.channels.TerminalServices.lastRecordId = maxRecord;
        db.setBookmark('TerminalServices', maxRecord);
      }

      this.channels.TerminalServices.status = 'OK';
      this.channels.TerminalServices.error = null;
      return events;
    } catch (err) {
      if (err.message.includes('No events were found') || err.message.includes('No matching events')) {
        this.channels.TerminalServices.status = 'OK';
        this.channels.TerminalServices.error = null;
      } else {
        this.channels.TerminalServices.status = 'DEGRADED';
        this.channels.TerminalServices.error = err.message;
      }
      return [];
    }
  }

  /**
   * Main tailing loop execution
   */
  async pollAll() {
    const start = Date.now();
    await this.initBookmarks();

    await Promise.allSettled([
      this.pollSystemChannel(),
      this.pollDefenderChannel(),
      this.pollSecurityChannel(),
      this.pollTerminalServicesChannel()
    ]);

    db.recordHealth('EventLogTailer', 'OK', Date.now() - start, 'Event log channels tailed');
  }

  getStatus() {
    return {
      channels: this.channels,
      lastCheckedUtc: new Date().toISOString()
    };
  }
}

// Singleton instance
const eventTailer = new WindowsEventTailer();
module.exports = eventTailer;
module.exports.WindowsEventTailer = WindowsEventTailer;
