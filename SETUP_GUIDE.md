# Setup and Deployment Guide: My Laptop Guard

This guide provides clean, step-by-step instructions to set up, configure, test, and run My Laptop Guard on any Windows machine.

---

## 1. System Requirements

- Operating System: Windows 10 or Windows 11 (64-bit)
- Shell: PowerShell 5.1 or PowerShell 7+
- Runtime: Node.js LTS (Version 20.x, 22.x, or 24.x recommended)
- Network: Local machine only (Binds strictly to 127.0.0.1)

---

## 2. Step-by-Step Installation on a New Device

### Step 1: Install Node.js
If Node.js is not already installed on the target laptop:
1. Download Node.js LTS from: https://nodejs.org/
2. Run the installer and verify in PowerShell:
   ```powershell
   node -v
   npm -v
   ```

### Step 2: Clone or Download the Repository
Open PowerShell and navigate to your desired directory:
```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL> my-laptop-guard
cd my-laptop-guard
```

### Step 3: Install Dependencies
Run npm install to pull required packages (Express, Socket.IO, dotenv):
```powershell
npm install
```

### Step 4: Configure the Environment File
Copy the example configuration file to create your active `.env`:
```powershell
Copy-Item .env.example .env
```
Default configuration values:
- `HOST`: 127.0.0.1 (Local loopback only)
- `PORT`: 3000
- `POLL_INTERVAL_MS`: 3000 (Checks connections every 3 seconds)
- `DEFENDER_POLL_INTERVAL_MS`: 30000 (Checks Defender every 30 seconds)
- `STARTUP_POLL_INTERVAL_MS`: 60000 (Checks startup items every 60 seconds)
- `RETENTION_DAYS`: 7 (Prunes logs older than 7 days)
- `API_AUTH_TOKEN`: laptop-guard-local-token-change-me

### Step 5: Verify Permissions and Subsystems
Run the built-in diagnostic script:
```powershell
npm run check-perms
```
This checks:
- Current user elevation (Standard User vs. Administrator)
- Node.js runtime accessibility
- Windows Defender WMI interface status
- Windows Firewall netsh interface status
- Port 3000 binding availability

### Step 6: Run Automated Self-Tests
Verify that all 44 subsystem tests pass on the target machine:
```powershell
npm test
```
Expected output:
`TEST RESULTS: 44 PASSED, 0 FAILED`

---

## 3. Running the Application

### Option A: Standard Run (Terminal Window Active)
To run the server with real-time console logs:
```powershell
npm start
```
Once started, open your web browser and navigate to:
```
http://127.0.0.1:3000
```
To stop the server, press `Ctrl + C` in the PowerShell window.

---

### Option B: Run with Administrator Privileges (Enables 1-Click Firewall Blocking)
To allow the web dashboard to directly add Windows Firewall blocking rules:
1. Click the Windows Start menu.
2. Type `PowerShell`.
3. Right-click `Windows PowerShell` and select `Run as administrator`.
4. Navigate to the project folder and start:
   ```powershell
   cd C:\path\to\my-laptop-guard
   npm start
   ```

---

### Option C: Run in Background as a Windows Service (Autostarts on Logon)
To have My Laptop Guard run silently in the background whenever you log into Windows:
```powershell
npm run install-service
```
Details:
- Registers a Windows Scheduled Task named `MyLaptopGuard_BackgroundWorker`.
- Runs completely in the background without keeping a console window open.
- Automatically recovers and restarts on failure.
- Visible in Task Manager under Background Processes.

To stop and remove the background service at any time:
```powershell
npm run uninstall-service
```

---

## 4. Git Push Preparation

Before pushing this repository to GitHub, verify that your `.gitignore` excludes local data and credentials:
```
node_modules/
.env
.env.local
data/*.db
data/*.db-wal
data/*.db-shm
*.log
```

To initialize and push to your GitHub repository:
```powershell
git init
git add .
git commit -m "feat: initial commit of My Laptop Guard background worker"
git branch -M main
git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

---

## 5. Summary of Common Commands

| Command | Purpose |
| :--- | :--- |
| `npm install` | Installs project dependencies |
| `npm test` | Runs the 44 automated tests |
| `npm run check-perms` | Runs permissions and subsystem diagnostics |
| `npm start` | Starts dashboard server at http://127.0.0.1:3000 |
| `npm run install-service` | Installs Windows autostart background task |
| `npm run uninstall-service` | Removes Windows background task |
