# Guardian - Personal Security & AI Threat Monitor (macOS Edition)

Guardian is a lightweight, 100% offline personal cybersecurity background service designed for Apple MacBooks (M1/M2/M3/M4 Apple Silicon & Intel) running macOS Sonoma, Ventura, or Monterey.

---

## ⚡ 1-Minute One-Click Installation on Mac

1. **Extract the Package**:
   - Double-click `Guardian-v1.0.0-macOS.zip` or extract `Guardian-v1.0.0-macOS.tar.gz`.

2. **Run the Installer**:
   - Double-click **`Install-Guardian.command`** in Finder.
   - *(If macOS displays an unidentified developer prompt, right-click `Install-Guardian.command` and choose **Open**).*

3. **That's It!**:
   - Guardian registers a background daemon with macOS `launchd` (`~/Library/LaunchAgents/com.guardian.laptopdefense.plist`).
   - It will automatically run silently 24/7 every time you log in to your MacBook.
   - It opens in standalone desktop application window mode at `http://127.0.0.1:3000`.
   - A native **`Guardian.app`** is created in your `~/Applications` folder.

---

## 🚀 How to Launch Guardian Anytime
- Double-click **`Guardian.app`** in `~/Applications` or Finder.
- Or double-click **`Launch-Guardian-App.command`**.
- Or open your browser to `http://127.0.0.1:3000`.

---

## 🛡️ Built-in macOS Features
- **Socket & Network Audit**: Continuous inspection of inbound and outbound sockets via `lsof` and `netstat`.
- **Apple XProtect, Gatekeeper & SIP Telemetry**: Audits system integrity protection and malware defenses.
- **Background Persistence Monitor**: Inspects `~/Library/LaunchAgents`, `/Library/LaunchAgents`, and `/Library/LaunchDaemons` for suspicious backdoors.
- **Remote Access Detection**: Detects active SSH logons, Screen Sharing, AnyDesk, TeamViewer, RustDesk, and Cloudflare Tunnels.
- **Guardian AI (Local RAG & Offline Assistant)**: Connects to local Ollama (`qwen2.5:1.5b` with Apple Silicon Metal acceleration) or embedded Expert RAG.

---

## 🧹 How to Cleanly Uninstall
- Double-click **`Uninstall-Guardian.command`**.
- It safely stops the background daemon, unregisters the `launchd` service, and removes `Guardian.app`.
