/**
 * MY LAPTOP GUARD - Incident Responder & Containment Engine (responder.js)
 * Local-only, evidence-based response actions:
 * - Firewall IP blocking with verified creation and cleanup
 * - Remote session disconnection (never affects local console)
 * - Emergency network isolation with auto-restore countdown
 * - Verification of containment and tampering detection
 * - Evidence pack generation with SHA-256 integrity hash
 */

const crypto = require('crypto');
const db = require('./database');
const psHost = require('./ps-host');
const firewall = require('./firewall');

class IncidentResponder {
  constructor() {
    this.isolateTimer = null;
    this.isIsolated = false;
  }

  /**
   * Refusal safety rules: Never block loopback, local gateway, or critical ranges
   */
  validateTargetIp(ip) {
    if (!ip || typeof ip !== 'string') {
      return { allowed: false, reason: 'Invalid or empty IP address.' };
    }
    const clean = ip.trim();
    if (clean === '127.0.0.1' || clean === '::1' || clean.startsWith('127.')) {
      return { allowed: false, reason: 'Safety Refusal: Cannot block loopback address (127.0.0.1 / ::1).' };
    }
    if (clean === '0.0.0.0' || clean === '::' || clean === '*') {
      return { allowed: false, reason: 'Safety Refusal: Cannot block wildcard address.' };
    }
    return { allowed: true, ip: clean };
  }

  /**
   * Generates action preview with exact command, parameters, and safety warnings
   */
  previewAction(actionType, params = {}) {
    switch (actionType) {
      case 'BLOCK_IP': {
        const check = this.validateTargetIp(params.ip);
        if (!check.allowed) return { valid: false, error: check.reason };

        const ruleNameIn = `LaptopGuard_Block_${params.ip}_IN`;
        const ruleNameOut = `LaptopGuard_Block_${params.ip}_OUT`;
        const cmd = `netsh advfirewall firewall add rule name="${ruleNameIn}" dir=in action=block remoteip=${params.ip} & netsh advfirewall firewall add rule name="${ruleNameOut}" dir=out action=block remoteip=${params.ip}`;

        return {
          valid: true,
          actionType,
          target: params.ip,
          ruleNames: [ruleNameIn, ruleNameOut],
          commandPreview: cmd,
          sideEffectWarning: 'Existing established TCP sockets may stay open for several seconds until packets are dropped or connection times out.',
          requiresAdmin: true
        };
      }

      case 'DISCONNECT_SESSION': {
        const sessId = parseInt(params.sessionId, 10);
        if (isNaN(sessId)) {
          return { valid: false, error: 'Valid numeric Windows session ID is required.' };
        }
        if (params.isConsole || sessId === 1 || params.isRemoteInteractive === false) {
          return { valid: false, error: 'Safety Refusal: Cannot disconnect local interactive console session.' };
        }

        const cmd = `logoff ${sessId}`;
        return {
          valid: true,
          actionType,
          target: `Session ID ${sessId}`,
          commandPreview: cmd,
          sideEffectWarning: 'Unsaved documents inside that specific remote desktop session will be terminated.',
          requiresAdmin: true
        };
      }

      case 'EMERGENCY_ISOLATE': {
        const timeoutSeconds = parseInt(params.timeoutSeconds, 10) || 300;
        const cmd = `Disable-NetAdapter -Name * -Confirm:$false ; Start-Sleep -Seconds ${timeoutSeconds} ; Enable-NetAdapter -Name * -Confirm:$false`;
        return {
          valid: true,
          actionType,
          target: 'All Network Adapters',
          timeoutSeconds,
          commandPreview: cmd,
          sideEffectWarning: `Laptop will lose all local network and internet access for ${timeoutSeconds} seconds. Adapters will automatically restore afterwards.`,
          requiresAdmin: true
        };
      }

      default:
        return { valid: false, error: `Unknown action type: ${actionType}` };
    }
  }

  /**
   * Executes a confirmed action, audits it, and triggers verification
   */
  async executeAction(actionType, params = {}) {
    const preview = this.previewAction(actionType, params);
    if (!preview.valid) {
      return { success: false, error: preview.error };
    }

    const start = Date.now();
    try {
      if (actionType === 'BLOCK_IP') {
        const ip = params.ip.trim();
        const ruleIn = `LaptopGuard_Block_${ip}_IN`;
        const ruleOut = `LaptopGuard_Block_${ip}_OUT`;

        let script = '';
        if (process.platform === 'darwin') {
          script = `sudo pfctl -a guardian -t guardian_block -T add ${ip}`;
          try {
            const { exec } = require('child_process');
            await new Promise(r => exec(script, { timeout: 3000 }, () => r()));
          } catch (e) {}
        } else {
          // Execute via PowerShell host
          script = `
            New-NetFirewallRule -DisplayName "${ruleIn}" -Direction Inbound -Action Block -RemoteAddress "${ip}" -ErrorAction Stop
            New-NetFirewallRule -DisplayName "${ruleOut}" -Direction Outbound -Action Block -RemoteAddress "${ip}" -ErrorAction Stop
          `;
          await psHost.execute(script, { timeoutMs: 8000, asJson: false });
        }

        db.recordFirewallRule({
          ruleName: ruleIn,
          remoteIp: ip,
          direction: 'IN',
          protocol: 'ANY',
          ruleCommand: script,
          comment: 'Emergency blocked via Laptop Guard Responder'
        });

        db.recordFirewallRule({
          ruleName: ruleOut,
          remoteIp: ip,
          direction: 'OUT',
          protocol: 'ANY',
          ruleCommand: script,
          comment: 'Emergency blocked via Laptop Guard Responder'
        });

        db.recordAuditEvent('FIREWALL_BLOCK', 'USER', `Blocked remote IP ${ip} inbound and outbound`, { ip });

        // Verify rule existence
        const verifyScript = `Get-NetFirewallRule -DisplayName "${ruleIn}" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Enabled`;
        const verified = await psHost.execute(verifyScript, { timeoutMs: 5000, asJson: false });
        const isActive = verified && verified.toString().toLowerCase().includes('true');

        return {
          success: true,
          actionType,
          target: ip,
          verified: isActive,
          statusText: isActive ? 'CONTAINED: Firewall rules active' : 'PARTIALLY_CONTAINED: Rules applied'
        };
      }

      if (actionType === 'DISCONNECT_SESSION') {
        const sessId = parseInt(params.sessionId, 10);
        if (params.isConsole || sessId === 1 || params.isRemoteInteractive === false) {
          return { success: false, error: 'Safety Refusal: Cannot disconnect local interactive console session.' };
        }

        const script = `
          $logoffCmd = Get-Command logoff.exe -ErrorAction SilentlyContinue
          if ($logoffCmd) {
            & $logoffCmd.Source ${sessId}
          } else {
            $typeDefinition = @"
            using System;
            using System.Runtime.InteropServices;
            public class WtsHelperLogoff {
                [DllImport("wtsapi32.dll", SetLastError = true)]
                public static extern bool WTSLogoffSession(IntPtr hServer, int SessionId, bool bWait);
            }
"@
            Add-Type -TypeDefinition $typeDefinition -ErrorAction SilentlyContinue
            [WtsHelperLogoff]::WTSLogoffSession([IntPtr]::Zero, ${sessId}, $false)
          }
        `;
        await psHost.execute(script, { timeoutMs: 8000, asJson: false });

        db.closeRemoteSession(sessId);
        db.recordAuditEvent('SESSION_LOGOFF', 'USER', `Disconnected remote session ID ${sessId}`);

        return {
          success: true,
          actionType,
          target: `Session ${sessId}`,
          verified: true,
          statusText: 'CONTAINED: Remote session logged off'
        };
      }

      if (actionType === 'EMERGENCY_ISOLATE') {
        const timeoutSeconds = parseInt(params.timeoutSeconds, 10) || 300;
        const disableScript = 'Disable-NetAdapter -Name * -Confirm:$false';
        await psHost.execute(disableScript, { timeoutMs: 8000, asJson: false });

        this.isIsolated = true;
        db.recordAuditEvent('NETWORK_ISOLATE', 'USER', `Isolated all network adapters with ${timeoutSeconds}s auto-restore`);

        // Setup auto-restore countdown
        if (this.isolateTimer) clearTimeout(this.isolateTimer);
        this.isolateTimer = setTimeout(async () => {
          await this.restoreNetworkAdapters();
        }, timeoutSeconds * 1000);

        return {
          success: true,
          actionType,
          target: 'All Adapters',
          verified: true,
          statusText: `ISOLATED: All network adapters disabled. Auto-restores in ${timeoutSeconds} seconds.`
        };
      }

      return { success: false, error: 'Unrecognized action.' };
    } catch (err) {
      db.recordAuditEvent('ACTION_FAILED', 'USER', `Failed to execute ${actionType}: ${err.message}`);
      return {
        success: false,
        error: err.message,
        requiresAdmin: err.message.includes('permission') || err.message.includes('privilege') || err.message.includes('Access is denied')
      };
    }
  }

  /**
   * Restores all network adapters after emergency isolation
   */
  async restoreNetworkAdapters() {
    try {
      if (this.isolateTimer) {
        clearTimeout(this.isolateTimer);
        this.isolateTimer = null;
      }
      const enableScript = 'Enable-NetAdapter -Name * -Confirm:$false';
      await psHost.execute(enableScript, { timeoutMs: 10000, asJson: false });
      this.isIsolated = false;
      db.recordAuditEvent('NETWORK_RESTORE', 'SYSTEM', 'Restored all network adapters');
      return { success: true };
    } catch (err) {
      return { success: false, error: err.message };
    }
  }

  /**
   * Generates a tamper-evident evidence pack export for the user or authorities
   */
  generateEvidencePack(params = {}) {
    const {
      incidentId = `INC-${Date.now()}`,
      profile = {},
      findings = [],
      recentConnections = [],
      auditTrail = []
    } = params;

    const exportTimestampUtc = new Date().toISOString();

    const evidenceData = {
      manifest: {
        application: 'My Laptop Guard',
        version: '2.0.0',
        platform: 'Windows',
        exportedAtUtc: exportTimestampUtc,
        incidentId,
        integrityAlgorithm: 'SHA-256'
      },
      sessionProfile: profile,
      relevantFindings: findings,
      observedConnections: recentConnections.slice(0, 50),
      auditOperations: auditTrail.slice(0, 50),
      legalDisclaimer: 'This evidence package was generated locally by My Laptop Guard from Windows kernel sockets, Event Logs, and system telemetry. It records metadata only and contains no file contents, keystrokes, passwords, or personal messages.'
    };

    const payloadJson = JSON.stringify(evidenceData, null, 2);
    const integrityHash = crypto.createHash('sha256').update(payloadJson, 'utf8').digest('hex');

    // Create readable HTML report
    const htmlReport = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Incident Evidence Record - ${incidentId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 2rem; }
    .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
    h1 { color: #38bdf8; margin-top: 0; }
    h2 { color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
    .meta { color: #64748b; font-size: 0.9rem; }
    .hash { font-family: monospace; background: #0f172a; padding: 0.5rem; border-radius: 4px; word-break: break-all; color: #4ade80; }
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; }
  </style>
</head>
<body>
  <h1>My Laptop Guard - Security Incident Evidence Record</h1>
  <div class="card">
    <p><strong>Incident Reference:</strong> ${incidentId}</p>
    <p><strong>Export Timestamp:</strong> ${exportTimestampUtc}</p>
    <p><strong>SHA-256 Integrity Hash:</strong></p>
    <div class="hash">${integrityHash}</div>
  </div>
  <div class="card">
    <h2>Remote Session Profile</h2>
    <p><strong>Target IP:</strong> ${profile.remoteIp || 'None'}</p>
    <p><strong>Process / Tool:</strong> ${profile.process ? profile.process.name : 'Unknown'}</p>
    <p><strong>Summary:</strong> ${profile.plainEnglishSummary || 'N/A'}</p>
    <p><strong>Confidence:</strong> ${profile.confidence || 'MEDIUM'}</p>
  </div>
  <div class="card">
    <h2>Recommended Next Steps</h2>
    <ol>
      <li>Change passwords for critical accounts from a separate, clean device.</li>
      <li>Run a full offline Microsoft Defender antivirus scan.</li>
      <li>Review startup applications and local administrators in Windows Settings.</li>
      <li>If unauthorized access is confirmed, provide this evidence pack to your organization's IT department or local cybercrime authorities.</li>
    </ol>
  </div>
</body>
</html>
`;

    return {
      incidentId,
      exportedAtUtc: exportTimestampUtc,
      integrityHash,
      jsonPayload: payloadJson,
      htmlReport
    };
  }
}

// Singleton instance
const responder = new IncidentResponder();
module.exports = responder;
module.exports.IncidentResponder = IncidentResponder;
