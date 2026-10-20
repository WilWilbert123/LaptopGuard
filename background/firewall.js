/**
 * MY LAPTOP GUARD - Windows Firewall Manager
 * Safely creates, verifies, and removes Windows Firewall blocking rules with strict validation,
 * admin privilege verification, traffic impact explanation, and audit logging.
 */

const { execFile, exec } = require('child_process');
const db = require('./database');

// IPv4 and IPv6 validation regexes
const IPV4_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/;
const IPV6_REGEX = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$/;

class FirewallManager {
  /**
   * Checks whether the current Node process is running with Windows Administrator privileges
   */
  async checkAdminPrivileges() {
    return new Promise((resolve) => {
      // 'net session' succeeds (code 0) only under elevated Administrator
      execFile('net.exe', ['session'], { timeout: 4000 }, (err) => {
        if (!err) {
          return resolve({ isAdmin: true, method: 'net session' });
        }
        // Fallback check with PowerShell
        exec('powershell -NoProfile -Command "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"', { timeout: 5000 }, (psErr, stdout) => {
          if (!psErr && stdout.trim().toLowerCase() === 'true') {
            resolve({ isAdmin: true, method: 'PowerShell' });
          } else {
            resolve({
              isAdmin: false,
              reason: 'Process is running in standard user mode without elevation.'
            });
          }
        });
      });
    });
  }

  /**
   * Validates and sanitizes an IP address to strictly prevent injection or hazardous self-blocks
   */
  validateIp(ip) {
    if (!ip || typeof ip !== 'string') {
      return { valid: false, error: 'IP address must be a valid non-empty string.' };
    }

    const cleanIp = ip.trim();

    // Check loopback / wildcard hazardous addresses
    if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost') {
      return {
        valid: false,
        error: 'Refusing to block loopback address (127.0.0.1 / ::1). Blocking localhost would disrupt essential local system operations.'
      };
    }

    if (cleanIp === '0.0.0.0' || cleanIp === '::' || cleanIp === '*') {
      return {
        valid: false,
        error: 'Refusing to block wildcard/unspecified address (0.0.0.0). This would sever all network connectivity.'
      };
    }

    // Verify format
    const isV4 = IPV4_REGEX.test(cleanIp);
    const isV6 = IPV6_REGEX.test(cleanIp) || cleanIp.includes(':');

    if (!isV4 && !isV6) {
      return { valid: false, error: `Invalid IP format: "${cleanIp}". Must be a valid IPv4 or IPv6 address.` };
    }

    return { valid: true, ip: cleanIp, isV4, isV6 };
  }

  /**
   * Generates a preview and safety explanation before executing a firewall rule
   */
  async generateRulePreview(ip, direction = 'BOTH', protocol = 'ANY') {
    const val = this.validateIp(ip);
    if (!val.valid) {
      return { success: false, error: val.error };
    }

    const adminCheck = await this.checkAdminPrivileges();
    const cleanIp = val.ip;
    const timestamp = Date.now();
    const ruleBase = `LaptopGuard_Block_${cleanIp.replace(/[:.]/g, '_')}_${timestamp}`;

    const netshOut = `netsh advfirewall firewall add rule name="${ruleBase}_OUT" dir=out action=block remoteip=${cleanIp} description="Created by My Laptop Guard"`;
    const netshIn = `netsh advfirewall firewall add rule name="${ruleBase}_IN" dir=in action=block remoteip=${cleanIp} description="Created by My Laptop Guard"`;

    const psOut = `New-NetFirewallRule -DisplayName "${ruleBase}_OUT" -Direction Outbound -Action Block -RemoteAddress "${cleanIp}" -Description "Created by My Laptop Guard"`;
    const psIn = `New-NetFirewallRule -DisplayName "${ruleBase}_IN" -Direction Inbound -Action Block -RemoteAddress "${cleanIp}" -Description "Created by My Laptop Guard"`;

    let affectedTraffic = '';
    if (direction === 'OUT') {
      affectedTraffic = `Blocks all OUTBOUND traffic from this laptop to ${cleanIp}.`;
    } else if (direction === 'IN') {
      affectedTraffic = `Blocks all INBOUND traffic from ${cleanIp} to this laptop.`;
    } else {
      affectedTraffic = `Blocks BOTH inbound and outbound traffic with ${cleanIp}.`;
    }

    return {
      success: true,
      remoteIp: cleanIp,
      direction,
      protocol,
      ruleName: ruleBase,
      isAdmin: adminCheck.isAdmin,
      affectedTraffic,
      exactCommands: {
        netsh: direction === 'OUT' ? [netshOut] : direction === 'IN' ? [netshIn] : [netshOut, netshIn],
        powershell: direction === 'OUT' ? [psOut] : direction === 'IN' ? [psIn] : [psOut, psIn]
      },
      elevationGuide: adminCheck.isAdmin ? null : {
        message: 'Administrator privileges are required to create Windows Firewall rules.',
        manualElevationStep: 'Open PowerShell as Administrator and run the command shown below, or restart My Laptop Guard in an elevated terminal.'
      },
      criticalDisclaimer: 'Note: Windows Firewall filters future packets matching this rule. Established TCP connections that were already active before rule creation may take several seconds to terminate or timeout.'
    };
  }

  /**
   * Executes creation of Windows Firewall rule
   */
  async executeBlockRule(ip, direction = 'BOTH', comment = '', confirmed = false) {
    if (!confirmed) {
      return {
        success: false,
        error: 'Confirmation required. You must explicitly confirm before creating a Windows Firewall rule.'
      };
    }

    const preview = await this.generateRulePreview(ip, direction);
    if (!preview.success) {
      return preview;
    }

    if (!preview.isAdmin) {
      return {
        success: false,
        error: 'Permission denied: Modifying Windows Firewall rules requires Administrator privileges.',
        isAdmin: false,
        commands: preview.exactCommands,
        elevationGuide: preview.elevationGuide
      };
    }

    const results = [];
    const commandsToRun = preview.exactCommands.netsh;

    for (const cmd of commandsToRun) {
      try {
        const out = await new Promise((resolve, reject) => {
          exec(cmd, { timeout: 10000 }, (error, stdout, stderr) => {
            if (error) {
              return reject(new Error(stderr || stdout || error.message));
            }
            resolve(stdout.trim());
          });
        });
        results.push({ cmd, output: out, success: true });
      } catch (err) {
        results.push({ cmd, error: err.message, success: false });
      }
    }

    const allSucceeded = results.every(r => r.success);
    if (allSucceeded) {
      // Record rule in SQLite
      db.recordFirewallRule({
        ruleName: preview.ruleName,
        remoteIp: preview.remoteIp,
        direction: direction,
        protocol: 'ANY',
        ruleCommand: commandsToRun.join(' && '),
        comment: comment || 'User initiated block',
        createdBy: 'user'
      });

      // Record audit event
      db.recordAuditEvent('FIREWALL_RULE_CREATED', 'USER', `Blocked remote IP: ${preview.remoteIp}`, {
        ruleName: preview.ruleName,
        direction,
        remoteIp: preview.remoteIp,
        commands: commandsToRun
      });

      return {
        success: true,
        message: `Successfully created Windows Firewall rule blocking ${preview.remoteIp}`,
        ruleName: preview.ruleName,
        commands: commandsToRun,
        disclaimer: preview.criticalDisclaimer
      };
    } else {
      return {
        success: false,
        error: 'One or more firewall rule additions failed.',
        details: results
      };
    }
  }

  /**
   * Removes a rule created by this application
   */
  async removeBlockRule(ruleName) {
    if (!ruleName || typeof ruleName !== 'string') {
      return { success: false, error: 'Rule name is required.' };
    }

    // Safety check: ensure rule name matches our managed prefix to avoid deleting system rules
    const sanitizedName = ruleName.trim().replace(/["';&|]/g, '');
    if (!sanitizedName.startsWith('LaptopGuard_Block_')) {
      return {
        success: false,
        error: 'Security safeguard: Only rules created by My Laptop Guard (starting with LaptopGuard_Block_) can be removed through this interface.'
      };
    }

    const adminCheck = await this.checkAdminPrivileges();
    if (!adminCheck.isAdmin) {
      return {
        success: false,
        error: 'Administrator privileges are required to delete Windows Firewall rules.',
        manualCommand: `netsh advfirewall firewall delete rule name="${sanitizedName}_OUT" & netsh advfirewall firewall delete rule name="${sanitizedName}_IN"`
      };
    }

    const deleteOutCmd = `netsh advfirewall firewall delete rule name="${sanitizedName}_OUT"`;
    const deleteInCmd = `netsh advfirewall firewall delete rule name="${sanitizedName}_IN"`;
    const deleteDirectCmd = `netsh advfirewall firewall delete rule name="${sanitizedName}"`;

    const runDelete = (cmd) => new Promise(res => {
      exec(cmd, { timeout: 8000 }, (err, stdout) => {
        res({ cmd, success: !err, output: stdout });
      });
    });

    await Promise.all([runDelete(deleteOutCmd), runDelete(deleteInCmd), runDelete(deleteDirectCmd)]);

    // Update database
    db.markFirewallRuleRemoved(sanitizedName);
    db.recordAuditEvent('FIREWALL_RULE_REMOVED', 'USER', `Removed firewall rule: ${sanitizedName}`);

    return {
      success: true,
      message: `Firewall rule ${sanitizedName} has been removed from Windows Firewall.`
    };
  }

  /**
   * Retrieves all rules currently tracked in database and checks live status
   */
  async getManagedRules() {
    return db.getFirewallRules();
  }

  /**
   * Retrieves active Windows Firewall profile statuses and existing system block rules
   */
  async getSystemFirewallStatus() {
    return new Promise((resolve) => {
      execFile('netsh.exe', ['advfirewall', 'show', 'allprofiles'], { timeout: 4000 }, (err, stdout) => {
        let domainOn = true;
        let privateOn = true;
        let publicOn = true;

        if (!err && stdout) {
          domainOn = /Domain Profile Settings:[\s\S]*?State\s+ON/i.test(stdout);
          privateOn = /Private Profile Settings:[\s\S]*?State\s+ON/i.test(stdout);
          publicOn = /Public Profile Settings:[\s\S]*?State\s+ON/i.test(stdout);
        }

        const psScript = '$rules = @(Get-NetFirewallRule -Action Block -Enabled True -ErrorAction SilentlyContinue); [PSCustomObject]@{ Total = $rules.Count; Sample = @($rules | Select-Object -First 20 -Property DisplayName, Direction) } | ConvertTo-Json -Depth 3 -Compress';

        exec(`powershell -NoProfile -Command "${psScript}"`, { timeout: 7000 }, (psErr, psStdout) => {
          let systemBlockRules = [];
          let totalCount = 0;
          if (!psErr && psStdout && psStdout.trim()) {
            try {
              const parsed = JSON.parse(psStdout);
              totalCount = parsed.Total || 0;
              const sample = parsed.Sample || [];
              systemBlockRules = Array.isArray(sample) ? sample : [sample];
            } catch (e) {}
          }

          resolve({
            profiles: {
              domain: domainOn ? 'ON' : 'OFF',
              private: privateOn ? 'ON' : 'OFF',
              public: publicOn ? 'ON' : 'OFF',
              policy: 'BlockInbound, AllowOutbound'
            },
            systemBlockRulesCount: totalCount || systemBlockRules.length,
            systemBlockRulesSample: systemBlockRules.map(r => ({
              name: r.DisplayName || 'Block Rule',
              direction: r.Direction === 1 ? 'INBOUND' : (r.Direction === 2 ? 'OUTBOUND' : 'UNKNOWN')
            }))
          });
        });
      });
    });
  }
}

module.exports = new FirewallManager();
