/**
 * MY LAPTOP GUARD - Remote Access & Spying Detection Rules
 * Evaluates active remote sessions, known RMM/RAT tools, reverse shell command channels,
 * and camera/microphone ConsentStore sensor access.
 * Correlates multiple independent indicators before escalating severity.
 */

const knownTools = require('./known-tools.json');

const REMOTE_RULES = {
  RULE_REMOTE_ACTIVE_SESSION: {
    id: 'RULE_REMOTE_ACTIVE_SESSION',
    title: 'Active Remote Interactive Desktop Session',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    mitreAttack: 'T1021.001 - Remote Services: Remote Desktop Protocol',
    whyFlagged: 'A user is logged in via a remote desktop session (RDP or Terminal Services).',
    remediation: 'Inspect who is connected, check client IP, and disconnect the session if unauthorized.'
  },
  RULE_REMOTE_TOOL_ACTIVE: {
    id: 'RULE_REMOTE_TOOL_ACTIVE',
    title: 'Remote Control Software Active With External Connection',
    severity: 'HIGH',
    confidence: 'HIGH',
    mitreAttack: 'T1219 - Remote Access Software',
    whyFlagged: 'A recognized remote administration or screen-sharing application has an active external network connection.',
    remediation: 'Confirm whether you or your organization started this remote session. If unexpected, stop the process or block its port.'
  },
  RULE_REMOTE_TOOL_INSTALLED: {
    id: 'RULE_REMOTE_TOOL_INSTALLED',
    title: 'Remote Control Tool Running in Background',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    mitreAttack: 'T1219 - Remote Access Software',
    whyFlagged: 'A remote access tool or management agent is running, but no active peer connection was detected.',
    remediation: 'If you did not install this tool, review whether it was installed by third-party software or unauthorized administrators.'
  },
  RULE_REMOTE_REVERSE_SHELL: {
    id: 'RULE_REMOTE_REVERSE_SHELL',
    title: 'Command Interpreter Connected to External Network Socket',
    severity: 'CRITICAL',
    confidence: 'HIGH',
    mitreAttack: 'T1059 - Command and Scripting Interpreter',
    whyFlagged: 'A command shell (cmd.exe, powershell.exe, bash) has an established TCP socket to an external IP address, characteristic of a reverse shell.',
    remediation: 'Terminate the suspicious shell process immediately, inspect its parent process, and trace any persistence items.'
  },
  RULE_SENSOR_CAMERA_ACTIVE: {
    id: 'RULE_SENSOR_CAMERA_ACTIVE',
    title: 'Webcam Sensor In Active Use',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    mitreAttack: 'T1125 - Video Capture',
    whyFlagged: 'Windows CapabilityAccessManager indicates the laptop camera is currently streaming video.',
    remediation: 'Check which application is accessing the camera. If you are not in a video call or recording, close the application.'
  },
  RULE_SENSOR_MIC_ACTIVE: {
    id: 'RULE_SENSOR_MIC_ACTIVE',
    title: 'Microphone Sensor In Active Use',
    severity: 'LOW',
    confidence: 'HIGH',
    mitreAttack: 'T1123 - Audio Capture',
    whyFlagged: 'Windows CapabilityAccessManager indicates an application is actively recording or streaming microphone audio.',
    remediation: 'Verify whether a voice chat, recording, or browser tab is using your microphone.'
  },
  RULE_REMOTE_RDP_LISTENING: {
    id: 'RULE_REMOTE_RDP_LISTENING',
    title: 'Remote Desktop Protocol (RDP) Port Exposed on 0.0.0.0',
    severity: 'HIGH',
    confidence: 'HIGH',
    mitreAttack: 'T1021.001 - Remote Services: Remote Desktop Protocol',
    whyFlagged: 'TCP Port 3389 is accepting incoming connections on all network interfaces with remote connections enabled.',
    remediation: 'Disable Remote Desktop in Windows Settings if not needed, or ensure Network Level Authentication (NLA) and firewall rules restrict access.'
  }
};

/**
 * Evaluates remote access telemetry snapshot and produces structured findings
 */
function evaluateRemoteAccessState(state = {}) {
  const findings = [];
  const {
    activeSessions = [],
    detectedTools = [],
    reverseShells = [],
    sensors = {},
    rdpConfig = {},
    listeningPorts = []
  } = state;

  // 1. Active Interactive Remote Sessions (RDP / Terminal Services)
  for (const session of activeSessions) {
    if (session.logonType === 10 || session.isRemoteInteractive) {
      findings.push({
        ruleId: REMOTE_RULES.RULE_REMOTE_ACTIVE_SESSION.id,
        title: REMOTE_RULES.RULE_REMOTE_ACTIVE_SESSION.title,
        severity: REMOTE_RULES.RULE_REMOTE_ACTIVE_SESSION.severity,
        confidence: REMOTE_RULES.RULE_REMOTE_ACTIVE_SESSION.confidence,
        processName: 'TermService',
        remoteIp: session.clientIp || null,
        explanation: `Active remote desktop session ID ${session.sessionId || session.logonId} connected as user "${session.username || 'Unknown'}" from client "${session.clientName || session.clientIp || 'Remote Client'}".`,
        evidence: [
          `LogonType: ${session.logonType} (RemoteInteractive)`,
          `Client Machine / IP: ${session.clientName || 'N/A'} / ${session.clientIp || 'N/A'}`,
          `Logon Time: ${session.logonTime || 'Active'}`
        ],
        remediation: REMOTE_RULES.RULE_REMOTE_ACTIVE_SESSION.remediation
      });
    }
  }

  // 2. Known Remote Control Software
  for (const tool of detectedTools) {
    if (tool.hasActiveConnection) {
      findings.push({
        ruleId: REMOTE_RULES.RULE_REMOTE_TOOL_ACTIVE.id,
        title: `${tool.name} Has Active Network Connection`,
        severity: REMOTE_RULES.RULE_REMOTE_TOOL_ACTIVE.severity,
        confidence: REMOTE_RULES.RULE_REMOTE_TOOL_ACTIVE.confidence,
        processName: tool.processName,
        pid: tool.pid,
        remoteIp: tool.remoteIp || null,
        explanation: `${tool.name} is currently running (PID ${tool.pid}) with an established external socket to ${tool.remoteIp || 'remote peer'}:${tool.remotePort || 'N/A'}.`,
        evidence: [
          `Category: ${tool.category}`,
          `Process: ${tool.processName} (PID ${tool.pid})`,
          `Remote Destination: ${tool.remoteIp}:${tool.remotePort}`
        ],
        remediation: REMOTE_RULES.RULE_REMOTE_TOOL_ACTIVE.remediation
      });
    } else if (tool.isRunning) {
      findings.push({
        ruleId: REMOTE_RULES.RULE_REMOTE_TOOL_INSTALLED.id,
        title: `${tool.name} Running in Background`,
        severity: REMOTE_RULES.RULE_REMOTE_TOOL_INSTALLED.severity,
        confidence: REMOTE_RULES.RULE_REMOTE_TOOL_INSTALLED.confidence,
        processName: tool.processName,
        pid: tool.pid,
        explanation: `${tool.name} is running in the background as a process or service, but has no active remote peer socket at this instant.`,
        evidence: [
          `Category: ${tool.category}`,
          `Process / Service: ${tool.processName || tool.serviceName}`,
          `Default Ports: ${tool.defaultPorts.join(', ') || 'Dynamic'}`
        ],
        remediation: REMOTE_RULES.RULE_REMOTE_TOOL_INSTALLED.remediation
      });
    }
  }

  // 3. Reverse Shell Command Channels
  for (const shell of reverseShells) {
    findings.push({
      ruleId: REMOTE_RULES.RULE_REMOTE_REVERSE_SHELL.id,
      title: `${shell.processName} External Socket (Potential Reverse Shell)`,
      severity: REMOTE_RULES.RULE_REMOTE_REVERSE_SHELL.severity,
      confidence: REMOTE_RULES.RULE_REMOTE_REVERSE_SHELL.confidence,
      processName: shell.processName,
      pid: shell.pid,
      remoteIp: shell.remoteIp,
      explanation: `Interpreter "${shell.processName}" (PID ${shell.pid}) has an active outbound TCP connection to ${shell.remoteIp}:${shell.remotePort}. Command interpreters rarely maintain direct external internet connections.`,
      evidence: [
        `Executable: ${shell.processPath || shell.processName}`,
        `Remote Destination: ${shell.remoteIp}:${shell.remotePort}`,
        `Local Socket: ${shell.localIp}:${shell.localPort}`
      ],
      remediation: REMOTE_RULES.RULE_REMOTE_REVERSE_SHELL.remediation
    });
  }

  // 4. Sensors (Webcam & Microphone in-use)
  if (sensors.webcam && sensors.webcam.inUse) {
    findings.push({
      ruleId: REMOTE_RULES.RULE_SENSOR_CAMERA_ACTIVE.id,
      title: `Webcam Sensor In Use by ${sensors.webcam.appName}`,
      severity: REMOTE_RULES.RULE_SENSOR_CAMERA_ACTIVE.severity,
      confidence: REMOTE_RULES.RULE_SENSOR_CAMERA_ACTIVE.confidence,
      processName: sensors.webcam.appName,
      explanation: `The laptop camera is currently streaming. Windows CapabilityAccessManager reports active access by "${sensors.webcam.appName}".`,
      evidence: [
        `App / Binary: ${sensors.webcam.appPath || sensors.webcam.appName}`,
        `Session Started: ${sensors.webcam.startTime || 'Now'}`
      ],
      remediation: REMOTE_RULES.RULE_SENSOR_CAMERA_ACTIVE.remediation
    });
  }

  if (sensors.microphone && sensors.microphone.inUse) {
    findings.push({
      ruleId: REMOTE_RULES.RULE_SENSOR_MIC_ACTIVE.id,
      title: `Microphone In Use by ${sensors.microphone.appName}`,
      severity: REMOTE_RULES.RULE_SENSOR_MIC_ACTIVE.severity,
      confidence: REMOTE_RULES.RULE_SENSOR_MIC_ACTIVE.confidence,
      processName: sensors.microphone.appName,
      explanation: `The laptop microphone is currently active. Windows CapabilityAccessManager reports access by "${sensors.microphone.appName}".`,
      evidence: [
        `App / Binary: ${sensors.microphone.appPath || sensors.microphone.appName}`,
        `Session Started: ${sensors.microphone.startTime || 'Now'}`
      ],
      remediation: REMOTE_RULES.RULE_SENSOR_MIC_ACTIVE.remediation
    });
  }

  // 5. RDP Port 3389 Listening on 0.0.0.0
  const rdpListener = listeningPorts.find(l => l.port === 3389 && l.ip === '0.0.0.0');
  if (rdpListener && rdpConfig.rdpEnabled) {
    findings.push({
      ruleId: REMOTE_RULES.RULE_REMOTE_RDP_LISTENING.id,
      title: REMOTE_RULES.RULE_REMOTE_RDP_LISTENING.title,
      severity: REMOTE_RULES.RULE_REMOTE_RDP_LISTENING.severity,
      confidence: REMOTE_RULES.RULE_REMOTE_RDP_LISTENING.confidence,
      processName: 'svchost.exe (TermService)',
      explanation: 'Remote Desktop Protocol service is active and listening on TCP port 3389 across all network interfaces (0.0.0.0). Anyone on the local network or internet (if port-forwarded) can reach your login screen.',
      evidence: [
        'Port: 3389 TCP',
        'Bound Interface: 0.0.0.0 (All Interfaces)',
        'fDenyTSConnections Registry Value: 0 (Allowed)'
      ],
      remediation: REMOTE_RULES.RULE_REMOTE_RDP_LISTENING.remediation
    });
  }

  return findings;
}

/**
 * Calculates remote access risk score (0-100) and risk tier
 */
function calculateRemoteRiskScore(state = {}) {
  let score = 0;
  const factors = [];

  const {
    activeSessions = [],
    detectedTools = [],
    reverseShells = [],
    sensors = {},
    rdpConfig = {},
    listeningPorts = []
  } = state;

  if (activeSessions.some(s => s.logonType === 10 || s.isRemoteInteractive)) {
    score += 50;
    factors.push({ name: 'Active Interactive Remote Desktop Session', weight: 50, severity: 'CRITICAL' });
  }

  if (reverseShells.length > 0) {
    score += 40;
    factors.push({ name: 'Command Shell Outbound Network Socket', weight: 40, severity: 'CRITICAL' });
  }

  const activeTool = detectedTools.find(t => t.hasActiveConnection);
  if (activeTool) {
    if (activeTool.category === 'Port Forwarding / Reverse Tunnel') {
      score += 15;
      factors.push({ name: `Active Reverse Tunnel (${activeTool.name})`, weight: 15, severity: 'LOW' });
    } else {
      score += 35;
      factors.push({ name: `Active Remote Control Connection (${activeTool.name})`, weight: 35, severity: 'HIGH' });
    }
  } else if (detectedTools.some(t => t.isRunning)) {
    score += 15;
    factors.push({ name: 'Remote Control Tool Running in Background', weight: 15, severity: 'MEDIUM' });
  }

  const rdpListener = listeningPorts.find(l => l.port === 3389 && l.ip === '0.0.0.0');
  if (rdpListener && rdpConfig.rdpEnabled) {
    score += 20;
    factors.push({ name: 'RDP Port 3389 Exposed on All Interfaces', weight: 20, severity: 'HIGH' });
  }

  if (sensors.webcam && sensors.webcam.inUse) {
    score += 10;
    factors.push({ name: `Camera In Use (${sensors.webcam.appName})`, weight: 10, severity: 'INFO' });
  }

  const clampedScore = Math.min(score, 100);
  let tier = 'NONE';
  if (clampedScore >= 60) tier = 'CRITICAL';
  else if (clampedScore >= 40) tier = 'HIGH';
  else if (clampedScore >= 20) tier = 'ELEVATED';
  else if (clampedScore > 0) tier = 'LOW';

  // Overall status banner determination
  let statusBanner = {
    code: 'NO_REMOTE_ACCESS',
    text: 'No remote access detected right now',
    severity: 'SAFE'
  };

  const hasInteractiveSession = activeSessions.some(s => s.logonType === 10 || s.isRemoteInteractive);

  if (hasInteractiveSession) {
    const s = activeSessions.find(s => s.logonType === 10 || s.isRemoteInteractive) || activeSessions[0];
    const who = s.username || 'Remote User';
    const from = s.clientIp || s.clientName || 'Network Client';
    statusBanner = {
      code: 'SESSION_ACTIVE',
      text: `Remote desktop session ACTIVE: user logged in (${who} from ${from})`,
      severity: 'CRITICAL'
    };
  } else if (activeTool) {
    if (activeTool.category === 'Port Forwarding / Reverse Tunnel') {
      statusBanner = {
        code: 'TUNNEL_ACTIVE',
        text: `Network Tunnel active: ${activeTool.name} connected to edge (${activeTool.remoteIp || 'Cloudflare Edge'})`,
        severity: 'INFO'
      };
    } else {
      statusBanner = {
        code: 'TOOL_ACTIVE',
        text: `Remote control software active: ${activeTool.name} connected to ${activeTool.remoteIp || 'remote client'}`,
        severity: 'HIGH'
      };
    }
  } else if (reverseShells.length > 0) {
    statusBanner = {
      code: 'SUSPICIOUS_INDICATORS',
      text: 'Suspicious remote-control indicators found: Command shell has active outbound socket',
      severity: 'CRITICAL'
    };
  } else if (detectedTools.some(t => t.isRunning)) {
    const tool = detectedTools.find(t => t.isRunning);
    statusBanner = {
      code: 'TOOL_IDLE',
      text: `Remote tool running in background (${tool.name})`,
      severity: 'WARNING'
    };
  }

  return {
    score: clampedScore,
    tier,
    factors,
    statusBanner
  };
}

module.exports = {
  REMOTE_RULES,
  knownTools,
  evaluateRemoteAccessState,
  calculateRemoteRiskScore
};
