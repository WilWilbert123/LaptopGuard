# MY LAPTOP GUARD

A lightweight, personal Windows laptop security background worker and live telemetry dashboard built using Node.js, Express, Socket.IO, SQLite, and vanilla JavaScript.

Designed specifically for monitoring your own Windows machine, My Laptop Guard collects real-time networking, hardware sensor, logon session, and security telemetry, highlights suspicious activity using transparent evidence-based heuristic rules, tracks Windows Defender health, monitors Windows security posture (0-100 score), detects remote access and covert spying tools, and provides safe, audited Windows Firewall and session containment controls.

---

## 1. Key Capabilities

- **Persistent PowerShell Engine (`ps-host.js`)**: Replaces high-overhead `powershell.exe` process spawning with a single, long-lived, sandboxed PowerShell child host communicating via JSON stdin/stdout pipes with per-command timeouts, boundary markers, and auto-restart backoff (< 50ms query latency).
- **Windows Event Log Tailer with Bookmarks (`event-tailer.js`)**: Reads and bookmarks Windows Event Logs (System 7045/104, Defender 1116/1117/5001, Security 4624/4625/1102, TerminalServices 21/24/25) so no events are dropped or duplicated across restarts.
- **Remote Access and Spying Detection (`remote-access.js`)**: Real-time status banner for active remote sessions. Identifies 30+ remote administration tools (AnyDesk, TeamViewer, RustDesk, ScreenConnect, Parsec, RMM agents), detects active RDP sessions, monitors webcam and microphone hardware streaming via Windows `CapabilityAccessManager` ConsentStore (`LastUsedTimeStop == 0`), and identifies reverse shells (PowerShell/cmd owning external outbound sockets).
- **Suspicious Outbound & Reverse Shell Detection (Section 16.1a)**: Evaluates command interpreters establishing outbound connections to raw IPs or common reverse-shell ports (4444, 4445, 5555, 8080, etc.), suspicious parent processes (Office, Browser, PDF reader), base64 obfuscation, and automated beaconing (mean interval and jitter percentage calculation).
- **Correlated Incidents Timeline**: Chains related multi-signal events into unified incidents (failed logons, RDP logons, persistence additions, outbound sockets) with timeline tracking and containment statuses.
- **Defensive Static Malware Analysis (Section 17 - `analyzer.js`)**: Completely isolated static reverse-engineering of local files with zero network requests, no dynamic execution, and no cloud uploads. Inspects PE headers, calculates Shannon entropy per section (>7.0 indicates packing), validates Authenticode signatures, redacts credentials, extracts passive IOCs, and exports Ghidra/x64dbg handoffs.
- **Live Connection Telemetry**: Inspects TCP connections, UDP endpoints, and listening sockets every 3 seconds. Tracks PID, process name, executable path, parent PID, user context, local/remote address, state, and connection direction (`OUTBOUND`, `INBOUND`, `LOCAL_LAN`, `LOOPBACK`).
- **Security Posture Score 0-100 (`posture.js`)**: Continuously audits 10 core Windows safeguards: Microsoft Defender real-time protection and signature age, Windows Firewall profiles (Domain/Private/Public), UAC elevation level, BitLocker drive encryption, Secure Boot state, TPM availability, SmartScreen filter, RDP Network Level Authentication (NLA), legacy SMBv1 protocol status, and disabled Guest accounts. Delivers an itemized letter grade (A-F) with setting paths and recommended actions.
- **Incident Containment and Forensics (`responder.js`, `identify.js`)**: Local evidence-only response dashboard. Builds Remote Session Profiles, enables guided 1-click Windows Firewall blocking with exact command previews, allows logging off unauthorized remote session IDs (strictly refusing to touch console session 1), provides Emergency Network Isolation with an automatic restore safety timer, and generates cryptographically signed Evidence Packs (JSON + readable HTML) with a SHA-256 integrity hash for law enforcement or IT admins.
- **Data Protection and Secret Redaction (`redact.js`)**: Automatically sanitizes tokens, passwords, API keys, bearer headers, connection strings, and base64 payloads from command lines and process telemetry before persisting to SQLite.
- **Local Isolation and Strict Privacy**: Binds strictly to `127.0.0.1`. All SQLite logs and telemetry stay exclusively on your laptop. Never captures keystrokes, screenshots, clipboard data, passwords, cookies, or document contents. Never connects back to or scans any remote IP.
- **Safe Windows Firewall Management**: Allows inspecting suspicious endpoints and safely generating or applying `netsh` / PowerShell blocking rules with admin privilege verification, traffic explanation, and 1-click elevation scripts.
- **Minimal Resource Footprint**: Consumes under 2% average CPU and under 150MB of memory at idle.

---

## 2. Project Architecture

```
my-laptop-guard/
├── background/
│   ├── server.js              # Main entrypoint: Express server, Socket.IO hub, API endpoints, supervisor
│   ├── monitor.js             # Telemetry engine: netstat polling, Defender query, startup inspection
│   ├── detector.js            # Evidence-based detection rules engine, severity scoring, deduplication
│   ├── database.js            # SQLite persistence layer with versioned schema migrations
│   ├── firewall.js            # Safe Windows Firewall rule creation, removal, verification, and previews
│   ├── ps-host.js             # Single long-lived persistent PowerShell worker process
│   ├── posture.js             # Security posture evaluator (0-100 score and letter grade)
│   ├── redact.js              # Sensitive credential, token, and secret redaction engine
│   ├── identify.js            # Remote session profile assembler and evidence correlator
│   ├── responder.js           # Containment actions, emergency isolation, and evidence pack generator
│   ├── analyzer.js            # Defensive static malware analysis, PE entropy, passive IOCs, Ghidra export
│   ├── notify.js              # Socket.IO event broadcaster and desktop toast notifications
│   ├── collectors/
│   │   ├── event-tailer.js    # Persistent Windows Event Log tailer with record bookmarks
│   │   └── remote-access.js   # Active logon sessions, ConsentStore webcam/mic, reverse shell beaconing
│   └── rules/
│       ├── known-tools.json   # Catalog of 30+ remote access tools, services, and default ports
│       └── remote-access.js   # Remote access heuristic rules and risk level calculations
├── public/
│   ├── index.html             # High-density security dashboard layout with tabs and status banners
│   ├── style.css              # Cockpit design system with dark/light mode toggle and glassmorphism
│   └── app.js                 # Vanilla JS client: real-time Socket.IO streams, search, modals, containment
├── scripts/
│   ├── install-service.ps1   # Registers background Windows Scheduled Task for autostart
│   ├── uninstall-service.ps1 # Unregisters task and terminates running background worker
│   └── check-permissions.ps1 # Diagnostics for Admin, Defender, Firewall, and port availability
├── test/
│   └── test-all.js            # Automated test suite (44 unit and integration tests)
├── SETUP_GUIDE.md             # Clean step-by-step setup guide for other devices
├── SECURITY.md                # Threat model, assumptions, and reporting
├── .env.example               # Reference environment configuration
├── .gitignore                 # Git exclusions
├── package.json               # Dependencies and lifecycle scripts
└── README.md                  # Comprehensive system documentation
```

---

## 3. Step-by-Step Setup Guide

### Prerequisites
- Operating System: Windows 10 or Windows 11 (64-bit)
- Runtime: Node.js LTS (Version 20.x, 22.x, or 24.x)
- Shell: PowerShell 5.1 or PowerShell 7+

### Step 1: Install Node.js
If Node.js is not yet installed on the machine:
1. Download Node.js LTS from: https://nodejs.org/
2. Run the installer and verify in PowerShell:
   ```powershell
   node -v
   npm -v
   ```

### Step 2: Clone or Download the Project
```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL> my-laptop-guard
cd my-laptop-guard
```

### Step 3: Install Dependencies
```powershell
npm install
```

### Step 4: Configure the Environment File
Copy the example configuration file:
```powershell
Copy-Item .env.example .env
```

### Step 5: Run Permissions Diagnostic
Run the built-in diagnostic script to verify system permissions and subsystem access:
```powershell
npm run check-perms
```

### Step 6: Run Automated Self-Tests
Verify that all 36 subsystem tests pass on the target machine:
```powershell
npm test
```
Expected output:
```
====================================================
TEST RESULTS: 36 PASSED, 0 FAILED
====================================================
```

---

## 4. How to Run

### Mode A: Standard Run (Terminal Window Active)
To start the application in the foreground with console logging:
```powershell
npm start
```
Once started, open your web browser and navigate to:
```
http://127.0.0.1:3000
```
To stop the server, press `Ctrl + C` in the PowerShell window.

### Mode B: Run with Administrator Privileges (Enables 1-Click Firewall and Containment)
To allow the web dashboard to directly add Windows Firewall blocking rules and manage session containment:
1. Click the Windows Start menu.
2. Type `PowerShell`.
3. Right-click `Windows PowerShell` and select `Run as administrator`.
4. Navigate to the project folder and start:
   ```powershell
   cd C:\path\to\my-laptop-guard
   npm start
   ```

### Mode C: Run in Background as a Windows Service (Autostarts on Logon)
To have My Laptop Guard run silently in the background whenever you log into Windows without keeping any terminal window open:
```powershell
npm run install-service
```
This registers a Windows Scheduled Task (`MyLaptopGuard_BackgroundWorker`) that runs `node background/server.js` with `-WindowStyle Hidden`, ensuring zero console popup.

To stop and remove the background service at any time:
```powershell
npm run uninstall-service
```

---

## 5. Security Posture Score (0-100)

The Posture module evaluates 10 key Windows security controls:

| Safeguard | Points | What It Checks |
| :--- | :---: | :--- |
| Microsoft Defender Antivirus | 20 | Real-time protection enabled, signature updated within 7 days |
| Windows Firewall Profiles | 15 | Domain, Private, and Public profiles all active |
| User Account Control (UAC) | 15 | ConsentPromptBehaviorAdmin > 0 (prevents silent elevation) |
| BitLocker Drive Encryption | 10 | Volume status on OS drive (C:) is fully encrypted |
| Secure Boot | 10 | UEFI Secure Boot enabled to protect bootloader integrity |
| Trusted Platform Module (TPM) | 10 | TPM chip activated and ready for hardware-backed credentials |
| Windows Defender SmartScreen | 5 | SmartScreen enabled for apps, downloads, and web browsing |
| Remote Desktop NLA | 5 | Network Level Authentication enforced for RDP connections |
| SMBv1 Protocol Disabled | 5 | Legacy, unencrypted SMBv1 protocol uninstalled/disabled |
| Guest Account Inactive | 5 | Built-in Windows Guest account is disabled |

---

## 6. Remote Access and Spying Detection

The Remote Access module answers: **"Is someone watching or controlling my laptop?"**

### 1. Active Remote Sessions
Monitors Windows logon sessions using `Win32_LogonSession` with LogonType 10 (RemoteInteractive/RDP). Displays session ID, username, state, client machine name, and logon duration.

### 2. Camera and Microphone Hardware Streaming
Monitors Windows `CapabilityAccessManager` ConsentStore (`HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore`). Detects desktop and packaged applications actively streaming video or audio (`LastUsedTimeStop == 0`).

### 3. Remote Control and RMM Software Catalog
Scans running processes and services against a catalog of 30+ remote administration tools: AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop, ScreenConnect, Splashtop, LogMeIn, GoToAssist, Zoho Assist, UltraVNC, TightVNC, RealVNC, TigerVNC, NoMachine, Parsec, Radmin, DWService, Supremo, Ammyy, RemotePC, Atera, N-able, Kaseya, NinjaRMM, MeshCentral, Tailscale, ZeroTier, ngrok, cloudflared, frp, and Chisel.

### 4. Reverse Shells and Covert Channels
Flags command interpreters (`powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`) that have spawned and established an active external TCP socket to an internet destination.

---

## 7. Suspicious Outbound & Reverse-Shell Detection (Section 16.1a)

In addition to inbound sessions, My Laptop Guard detects when this laptop has initiated an outbound socket that exhibits reverse-shell or command-channel indicators.

### Signals Evaluated (Combined defensively; never alerted on one alone):
1. **Interpreter Process**: `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `python.exe`, `node.exe`, or `wsl.exe` owning an established external socket.
2. **Raw IP Peer**: Outbound destination is an IP literal with no registered reverse-DNS hostname.
3. **Common Shell Port**: Destination port matches common listener ports (4444, 4445, 5555, 8080, 9001, etc.).
4. **Suspicious Parent Chain**: Interpreter was spawned by an Office application (`winword.exe`, `excel.exe`), a web browser, or a PDF reader.
5. **Obfuscated Command Line**: Arguments contain base64 payloads, `-EncodedCommand`, `-enc`, `IEX`, `DownloadString`, or reflective execution markers (stored secret-redacted).
6. **Beaconing Heuristics**: Calculates inter-connection arrival times and standard deviation jitter percentage. Connections exhibiting low jitter (<= 25%) and regular intervals between 2s and 600s are flagged as automated beacon-like activity.

---

## 8. Defensive Static Malware Analysis (Section 17 - `analyzer.js`)

Provides isolated, local-only static reverse engineering of suspicious files already present on your machine.

### Non-Negotiable Safety Boundaries:
- **Zero Network Traffic**: Never fetches files from the internet, never uploads files anywhere, and never connects to extracted IOCs.
- **Zero Dynamic Execution**: The analyzer inspects file bytes strictly via read-only buffers; it never executes or launches the sample.
- **System Directory Safeguard**: Refuses to inspect files inside core Windows system directories unless explicitly confirmed.
- **Honest Assessments**: Never claims a file is "clean" or "safe" — lists observed structural characteristics and heuristic indicators only.

### Capabilities:
- **PE Header Parsing**: Pure JavaScript parser extracts machine architecture, compile timestamp, subsystem, entry point RVA, image base, and section table.
- **Shannon Entropy Calculation**: Computes entropy in bits per byte for every section (`H = -sum(p * log2(p))`). Sections with entropy > 7.0 are flagged as packed or encrypted.
- **Passive IOC Extraction**: Regex patterns extract IPv4 literals, domains, URLs, email addresses, registry keys, file paths, and named mutexes from file content.
- **Credential Redaction**: Extracted printable strings are filtered and sanitized with secrets redacted.
- **Ghidra / x64dbg Handoff**: Generates a structured JSON handoff file containing entry points, base addresses, hashes, and architecture recommendations.
- **Self-Contained Report**: Generates a tamper-evident HTML report with a cryptographic SHA-256 integrity hash.

---

## 9. Incident Containment and Response

When unauthorized access is suspected, the Respond dashboard provides guided, audited local containment actions:

1. **Block Remote IP**: Generates and applies Windows Firewall rules prefixed with `LaptopGuard_Block_` blocking inbound and outbound traffic. Refuses loopback (`127.0.0.1`), private LANs, and wildcard addresses.
2. **Disconnect Session**: Logs off or disconnects a specific remote session ID via `quser.exe` or `logoff.exe`. Strictly refuses to disconnect the primary local console session (ID 1).
3. **Emergency Network Isolation**: Temporarily disables the active network adapter using `Disable-NetAdapter`. Includes an automatic restore safety timer (default: 10 minutes) to prevent accidental permanent lockouts.
4. **Evidence Pack Export**: Compiles all session details, process paths, redacted command lines, firewall actions, and audit logs into a portable JSON file and clean HTML report, signed with a cryptographic SHA-256 integrity hash.

---

## 10. What This Tool CANNOT Detect (Honest Limitations)

In the interest of honesty and realistic expectations:
- **No Kernel/Rootkit Detection**: Userland processes cannot reliably detect kernel-level rootkits, hypervisor implants, or driver-level vulnerabilities that compromise the Windows kernel.
- **No Hardware Keylogger Detection**: Physical inline keyloggers between your keyboard and USB port cannot be detected via Windows software APIs.
- **No Audio/Video Content Inspection**: This tool checks whether the webcam or mic sensor is in use by querying Windows ConsentStore timestamps. It does not record audio, view camera frames, or verify whether the physical camera LED is on.
- **No Remote Identity Attribution**: A remote IP address identifies a network socket endpoint. It may be a VPN exit node, Tor relay, cloud proxy, or a third-party compromised computer. This tool cannot determine the physical identity of an external user.
- **No Compromised Network/Router Detection**: If your local Wi-Fi router or ISP upstream equipment is compromised, traffic manipulation outside the laptop cannot be seen by local host monitoring.

---

## 11. Permissions and Administrator Privileges

| Feature | Standard User Mode | Elevated Administrator Mode |
| :--- | :---: | :---: |
| Real-time connection inspection | Yes | Yes |
| Process path identification | Userland processes | All system processes |
| Listening port inspection | Yes | Yes |
| Behavioral anomaly detection | Yes | Yes |
| ConsentStore camera/mic inspection | Yes | Yes |
| Windows Defender status query | Yes | Yes |
| Security Posture scoring | Yes | Yes |
| Suspicious Outbound & Beaconing | Yes | Yes |
| Static Malware Analysis & PE Entropy | Yes | Yes |
| Firewall rule preview & PowerShell copy | Yes | Yes |
| Direct 1-Click Firewall Rule Creation | Requires elevation | Yes |
| Remote Session Disconnect | Requires elevation | Yes |
| Emergency Network Isolation | Requires elevation | Yes |

---

## 12. Summary of Common Commands

| Task | Command |
| :--- | :--- |
| Install dependencies | `npm install` |
| Run test suite (44 tests) | `npm test` |
| Check system permissions | `npm run check-perms` |
| Start live server | `npm start` |
| Install background service | `npm run install-service` |
| Uninstall background service | `npm run uninstall-service` |
| Open dashboard in browser | `http://127.0.0.1:3000` |

---

## 11. Security and Privacy Guarantees

- **No Remote Telemetry**: Telemetry is never uploaded to any external server or cloud service.
- **No User Surveillance**: Does not record keystrokes, capture desktop screenshots, read clipboard buffers, or inspect browser history/passwords.
- **Loopback Isolation**: Server refuses connections from external network interfaces by binding strictly to `127.0.0.1`.
- **Secret Redaction**: Passwords, API tokens, bearer headers, and connection strings are redacted before persistence.
- **Bounded Growth**: Automatic SQLite database pruning ensures your disk space is never exhausted.

---

## 12. License

Personal use license — built exclusively for monitoring personal Windows laptop security.
#   L a p t o p G u a r d  
 