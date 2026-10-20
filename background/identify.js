/**
 * MY LAPTOP GUARD - Remote Session Identification Engine (identify.js)
 * Assembles a comprehensive Remote Session Profile strictly from local Windows evidence.
 * NEVER connects back to or scans remote hosts. Local forensics only.
 */

const crypto = require('crypto');
const db = require('./database');
const { redactSensitiveData } = require('./redact');
const { knownTools } = require('./rules/remote-access');

class RemoteSessionIdentifier {
  /**
   * Builds an evidence-backed Remote Session Profile
   */
  buildSessionProfile(params = {}) {
    const {
      remoteIp = '',
      remotePort = 0,
      protocol = 'TCP',
      pid = 0,
      processName = '',
      processPath = '',
      commandLine = '',
      sessionId = null,
      username = '',
      domain = '',
      clientName = '',
      logonType = null
    } = params;

    const profileId = crypto.randomBytes(8).toString('hex');
    const nowUtc = new Date().toISOString();

    // 1. Identify Process and Tool
    let toolMatch = null;
    const lowerName = (processName || '').toLowerCase();
    for (const tool of knownTools) {
      if (tool.processNames.some(p => p.toLowerCase() === lowerName)) {
        toolMatch = {
          id: tool.id,
          name: tool.name,
          category: tool.category,
          isDangerousUnattended: tool.isDangerousUnattended
        };
        break;
      }
    }

    // 2. Query known process info from database if missing
    let resolvedPath = processPath;
    let resolvedCmd = commandLine;
    if (pid && (!resolvedPath || !resolvedCmd)) {
      const knownProc = db.getProcess(pid);
      if (knownProc) {
        resolvedPath = resolvedPath || knownProc.executable_path;
        resolvedCmd = resolvedCmd || knownProc.command_line;
      }
    }

    const cleanCmd = resolvedCmd ? redactSensitiveData(resolvedCmd) : null;

    // 3. Assemble Windows Session Info
    const windowsSession = {
      sessionId: sessionId || (logonType === 10 ? 'Remote' : 'Local/Console'),
      username: username || 'Current User',
      domain: domain || 'WORKGROUP',
      logonType: logonType || (lowerName.includes('termservice') || lowerName.includes('mstsc') ? 10 : 2),
      clientName: clientName || (remoteIp ? `Client-${remoteIp}` : 'Unknown Client'),
      isRemoteInteractive: logonType === 10
    };

    // 4. Determine Confidence & Summary
    let confidence = 'MEDIUM';
    const evidenceList = [];

    if (remoteIp) {
      evidenceList.push(`Remote Endpoint: ${remoteIp}:${remotePort || 'N/A'} (${protocol})`);
    }

    if (processName) {
      evidenceList.push(`Handling Process: ${processName} (PID ${pid || 'Unknown'})`);
    }

    if (toolMatch) {
      confidence = 'HIGH';
      evidenceList.push(`Recognized Remote Software: ${toolMatch.name} (${toolMatch.category})`);
    }

    if (windowsSession.isRemoteInteractive) {
      confidence = 'HIGH';
      evidenceList.push(`Windows Terminal Services Logon Type 10 (RemoteInteractive)`);
    }

    const toolDesc = toolMatch ? toolMatch.name : (processName || 'Network socket');
    const plainEnglishSummary = remoteIp
      ? `A connection was observed from or to ${remoteIp} handled by ${toolDesc} as user "${windowsSession.username}".`
      : `An active session or remote management software (${toolDesc}) is active on this laptop.`;

    // 5. Recommended Safe Containment Actions
    const recommendedActions = [
      {
        id: 'ACTION_BLOCK_IP',
        title: `Block IP ${remoteIp} in Windows Firewall`,
        description: 'Instantly prevents any further inbound or outbound network packets to this IP address.',
        safe: true,
        requiresAdmin: true
      },
      {
        id: 'ACTION_DISCONNECT_SESSION',
        title: `Disconnect Remote Session ID ${windowsSession.sessionId}`,
        description: 'Immediately logs off or severs the remote user session without terminating local console access.',
        safe: true,
        requiresAdmin: true
      },
      {
        id: 'ACTION_EMERGENCY_ISOLATE',
        title: 'Emergency Network Adapter Isolation',
        description: 'Disables network adapters to completely isolate laptop from LAN and internet, with 5-minute auto-restore timer.',
        safe: true,
        requiresAdmin: true
      }
    ];

    return {
      profileId,
      assembledAtUtc: nowUtc,
      confidence,
      remoteIp,
      remotePort,
      protocol,
      toolMatch,
      process: {
        pid,
        name: processName,
        path: resolvedPath,
        commandLine: cleanCmd
      },
      windowsSession,
      evidenceList,
      plainEnglishSummary,
      recommendedActions,
      limitsDisclaimer: 'NOTICE: An IP address identifies a network interface or routing node, not proof of a specific human identity. Connections may be routed through commercial VPNs, proxies, public Wi-Fi, or compromised relays.'
    };
  }
}

// Singleton instance
const identifier = new RemoteSessionIdentifier();
module.exports = identifier;
module.exports.RemoteSessionIdentifier = RemoteSessionIdentifier;
