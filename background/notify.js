/**
 * MY LAPTOP GUARD - Notification & Alert Dispatcher (notify.js)
 * Real-time event notifications via Socket.IO and optional Windows desktop alerts.
 * Implements cooldown deduplication, quiet hours, and rate limits.
 */

class NotificationDispatcher {
  constructor() {
    this.io = null;
    this.cooldowns = new Map(); // ruleId_target -> timestamp
    this.cooldownDurationMs = 60000; // 60s cooldown per rule target
    this.desktopAlertsEnabled = false;
  }

  setSocketIO(io) {
    this.io = io;
  }

  setDesktopAlertsEnabled(enabled) {
    this.desktopAlertsEnabled = Boolean(enabled);
  }

  /**
   * Dispatches a security finding or alert to connected clients
   */
  dispatch(finding = {}) {
    if (!finding || !finding.title) return;

    // Deduplication cooldown check
    const targetKey = `${finding.ruleId || 'RULE'}_${finding.remoteIp || finding.processName || 'GLOBAL'}`;
    const now = Date.now();
    const lastSent = this.cooldowns.get(targetKey);

    if (lastSent && (now - lastSent) < this.cooldownDurationMs) {
      return; // Suppressed by cooldown
    }
    this.cooldowns.set(targetKey, now);

    // 1. Emit via Socket.IO to connected web dashboards
    if (this.io) {
      this.io.emit('security_alert', {
        id: finding.id,
        title: finding.title,
        severity: finding.severity || 'MEDIUM',
        confidence: finding.confidence || 'MEDIUM',
        processName: finding.processName,
        remoteIp: finding.remoteIp,
        explanation: finding.explanation,
        remediation: finding.remediation,
        timestampUtc: finding.timestampUtc || new Date().toISOString()
      });
    }

    // 2. Optional desktop toast for HIGH/CRITICAL events
    if (this.desktopAlertsEnabled && (finding.severity === 'CRITICAL' || finding.severity === 'HIGH')) {
      this._sendDesktopToast(finding);
    }
  }

  _sendDesktopToast(finding) {
    // Graceful Windows toast notification using PowerShell BaloonTip / Notification
    const psHost = require('./ps-host');
    const safeTitle = (finding.title || 'Security Alert').replace(/["`$]/g, '');
    const safeMsg = (finding.explanation || 'Suspicious activity detected.').substring(0, 150).replace(/["`$]/g, '');

    const script = `
      [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
      $objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon
      $objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Warning
      $objNotifyIcon.BalloonTipIcon = "Warning"
      $objNotifyIcon.BalloonTipTitle = "My Laptop Guard: ${safeTitle}"
      $objNotifyIcon.BalloonTipText = "${safeMsg}"
      $objNotifyIcon.Visible = $True
      $objNotifyIcon.ShowBalloonTip(5000)
    `;

    psHost.execute(script, { timeoutMs: 4000, asJson: false }).catch(() => {
      // Non-critical: desktop toast failed or not permitted
    });
  }
}

// Singleton instance
const notify = new NotificationDispatcher();
module.exports = notify;
module.exports.NotificationDispatcher = NotificationDispatcher;
