#!/usr/bin/env bash
# =====================================================================
# GUARDIAN - macOS Installer & Service Provisioner
# Installs Guardian as a persistent, offline local security background
# service on macOS (MacBook Pro, Air, iMac, Mac Mini) with launchd autostart
# and native standalone desktop application launcher.
# =====================================================================

set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
WHITE='\033[1;37m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}   GUARDIAN - Personal MacBook Security Installer   ${NC}"
echo -e "${CYAN}====================================================${NC}"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# 1. Target Directory
if [ "$EUID" -eq 0 ]; then
    TARGET_DIR="/Applications/Guardian"
    APP_BUNDLE="/Applications/Guardian.app"
    PLIST_DIR="/Library/LaunchDaemons"
    PLIST_FILE="$PLIST_DIR/com.guardian.laptopdefense.plist"
    echo -e "${GREEN}[OK] Running as Administrator (root).${NC}"
else
    TARGET_DIR="$HOME/Applications/Guardian"
    APP_BUNDLE="$HOME/Applications/Guardian.app"
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/com.guardian.laptopdefense.plist"
    echo -e "${YELLOW}[INFO] Running as user $(whoami).${NC}"
fi

echo -e "${WHITE}[1/6] Destination: $TARGET_DIR${NC}"
mkdir -p "$TARGET_DIR"
mkdir -p "$TARGET_DIR/data"
mkdir -p "$PLIST_DIR"

# 2. Check for Node.js
echo -e "${WHITE}[2/6] Verifying Node.js runtime...${NC}"
NODE_BIN=""
if command -v node >/dev/null 2>&1; then
    NODE_BIN="$(command -v node)"
elif [ -f "/opt/homebrew/bin/node" ]; then
    NODE_BIN="/opt/homebrew/bin/node"
elif [ -f "/usr/local/bin/node" ]; then
    NODE_BIN="/usr/local/bin/node"
elif [ -n "$NVM_BIN" ] && [ -f "$NVM_BIN/node" ]; then
    NODE_BIN="$NVM_BIN/node"
fi

if [ -z "$NODE_BIN" ]; then
    echo -e "${YELLOW}[WARNING] Node.js was not found in your standard PATH.${NC}"
    echo "Please install Node.js (via https://nodejs.org or 'brew install node') to run Guardian."
    NODE_BIN="/usr/local/bin/node"
fi
echo -e "${GREEN}[OK] Node.js located: $NODE_BIN ($($NODE_BIN -v 2>/dev/null || echo 'unverified'))${NC}"

# 3. Copy Application Files
echo -e "${WHITE}[3/6] Installing application files...${NC}"
cp -R "$SOURCE_DIR/background" "$TARGET_DIR/"
cp -R "$SOURCE_DIR/public" "$TARGET_DIR/"
if [ -d "$SOURCE_DIR/node_modules" ]; then
    cp -R "$SOURCE_DIR/node_modules" "$TARGET_DIR/"
fi
cp -R "$SOURCE_DIR/installer" "$TARGET_DIR/"
cp "$SOURCE_DIR/package.json" "$TARGET_DIR/"
if [ -f "$SOURCE_DIR/.env" ]; then
    cp "$SOURCE_DIR/.env" "$TARGET_DIR/"
elif [ -f "$SOURCE_DIR/.env.example" ]; then
    cp "$SOURCE_DIR/.env.example" "$TARGET_DIR/.env"
fi

# 4. Create launchd Plist for Autostart
echo -e "${WHITE}[4/6] Configuring macOS launchd background daemon...${NC}"
cat <<EOF > "$PLIST_FILE"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.guardian.laptopdefense</string>
    <key>ProgramArguments</key>
    <array>
        <string>$NODE_BIN</string>
        <string>$TARGET_DIR/background/server.js</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$TARGET_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$TARGET_DIR/data/guardian.log</string>
    <key>StandardErrorPath</key>
    <string>$TARGET_DIR/data/guardian-err.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin</string>
    </dict>
</dict>
</plist>
EOF

# Unload previous service if running and reload
launchctl unload "$PLIST_FILE" 2>/dev/null || true
launchctl load -w "$PLIST_FILE"
echo -e "${GREEN}[OK] Background service registered with launchd.${NC}"

# 5. Create Native Guardian.app Bundle
echo -e "${WHITE}[5/6] Creating macOS Guardian.app desktop bundle...${NC}"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy logo icon
if [ -f "$TARGET_DIR/public/logo.png" ]; then
    cp "$TARGET_DIR/public/logo.png" "$APP_BUNDLE/Contents/Resources/AppIcon.png"
fi

# App Info.plist
cat <<EOF > "$APP_BUNDLE/Contents/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>Guardian</string>
    <key>CFBundleDisplayName</key>
    <string>Guardian Security</string>
    <key>CFBundleIdentifier</key>
    <string>com.guardian.security</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleExecutable</key>
    <string>Guardian</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon.png</string>
    <key>LSUIElement</key>
    <false/>
</dict>
</plist>
EOF

# App Executable Launcher Script
cat <<'EOF' > "$APP_BUNDLE/Contents/MacOS/Guardian"
#!/usr/bin/env bash
# Check if Guardian server is running on port 3000
if ! curl -s -m 1 http://127.0.0.1:3000/api/status >/dev/null 2>&1; then
    TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/Guardian"
    if [ -f "$TARGET_DIR/background/server.js" ]; then
        node "$TARGET_DIR/background/server.js" >/dev/null 2>&1 &
        sleep 1.5
    fi
fi

# Launch in Native Standalone App Window Mode (no browser tabs, no address bar)
if [ -d "/Applications/Microsoft Edge.app" ]; then
    open -na "Microsoft Edge" --args --app=http://127.0.0.1:3000 --app-id=GuardianSecurity --window-size=1360,860
elif [ -d "/Applications/Google Chrome.app" ]; then
    open -na "Google Chrome" --args --app=http://127.0.0.1:3000 --app-id=GuardianSecurity --window-size=1360,860
elif [ -d "/Applications/Brave Browser.app" ]; then
    open -na "Brave Browser" --args --app=http://127.0.0.1:3000 --app-id=GuardianSecurity --window-size=1360,860
else
    open "http://127.0.0.1:3000"
fi
EOF

chmod +x "$APP_BUNDLE/Contents/MacOS/Guardian"
echo -e "${GREEN}[OK] Native macOS application created at: $APP_BUNDLE${NC}"

# 6. Launch Guardian Now
echo -e "${WHITE}[6/6] Launching Guardian Security Cockpit...${NC}"
sleep 1.5
"$APP_BUNDLE/Contents/MacOS/Guardian" || true

echo ""
echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}   GUARDIAN INSTALLATION COMPLETE (macOS)           ${NC}"
echo -e "${CYAN}====================================================${NC}"
echo -e "• Status: Running 24/7 in background (Port 3000)"
echo -e "• Autostart: Enabled via launchd on user login"
echo -e "• Application: $APP_BUNDLE"
echo -e "• Dashboard: http://127.0.0.1:3000"
echo ""
