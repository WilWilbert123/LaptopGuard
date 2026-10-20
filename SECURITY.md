# SECURITY POLICY - MY LAPTOP GUARD

## 1. Threat Model

My Laptop Guard is an endpoint defense and telemetry auditing tool designed for personal Windows laptops. It operates as an unprivileged or elevated background Node.js process with a local-only web dashboard.

### Protected Assets
- Local telemetry data (process metadata, network sockets, Windows event bookmarks).
- The laptop's network configuration and Windows Firewall rules.
- Local user privacy (preventing remote surveillance without knowledge).

### Threat Actors Considered
1. **Covert Remote Access Tools / Spyware**: Unauthorized commercial remote desktop software, stalkerware, or reverse shells installed without the owner's knowledge to spy on or control the device.
2. **Network Attackers on Shared LANs**: Entities attempting to connect to listening ports or exploit exposed Windows services (such as RDP or SMB).
3. **Malware Establishing Persistence**: Unwanted binaries modifying Windows Registry Run keys or startup items to achieve survival across reboots.

---

## 2. Security Assumptions and Boundaries

### Assumptions
- The Windows operating system kernel, hypervisor, and firmware are fundamentally intact.
- The user is the rightful owner and operator of the laptop.
- The Node.js runtime and its dependencies are downloaded from trusted, integrity-verified sources.

### Boundaries and Non-Goals
- **No Kernel/Rootkit Protection**: This tool executes in userland. An attacker with kernel-level driver execution (`Ring 0`) can hide processes, hook network stacks, and forge telemetry.
- **No Hardware Security**: Physical keyloggers, rogue USB devices (e.g., BadUSB), and physical cold-boot attacks are outside the scope of software detection.
- **No Attack Back / Offense**: My Laptop Guard strictly observes local evidence. It will NEVER connect to, probe, scan, or exploit any remote machine.
- **No Telemetry Exfiltration**: No logs, statistics, or incident packs are ever sent to any remote cloud endpoint.

---

## 3. Tool Hardening Safeguards

1. **Localhost Binding**: The Express server and Socket.IO hub bind strictly to `127.0.0.1`. Remote machines on your local Wi-Fi or internet cannot access the dashboard.
2. **Secret Redaction**: Passwords, API tokens, bearer headers, and connection strings are automatically scrubbed from command-line arguments and script blocks before database persistence.
3. **Refusal Rules**: The incident responder strictly refuses to block loopback addresses (`127.0.0.1`, `::1`), private gateways, or disconnect console session ID 1.
4. **Input Validation**: All target IP addresses, ports, and session IDs are validated against strict regex patterns to prevent command injection into `netsh` or PowerShell commands.
5. **Emergency Restore Timer**: The emergency network isolation action enforces an auto-restore countdown to prevent accidental permanent lockouts.

---

## 4. Reporting Security Vulnerabilities

If you identify a security vulnerability or weakness in My Laptop Guard:

1. **Do not open a public GitHub issue.**
2. Document the exact steps to reproduce the vulnerability, along with system specifications (Windows build version, Node.js version, and elevation status).
3. Submit your report directly to the repository maintainer or security contact via email or encrypted private communication.
4. You will receive an acknowledgment within 48 hours, followed by a patch verification timeline.
