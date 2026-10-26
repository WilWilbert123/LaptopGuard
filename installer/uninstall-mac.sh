#!/usr/bin/env bash
# =====================================================================
# GUARDIAN - macOS Clean Uninstaller
# Unregisters launchd background daemon, stops running service,
# and cleans up application bundles.
# =====================================================================

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}   GUARDIAN - macOS Security Uninstaller            ${NC}"
echo -e "${CYAN}====================================================${NC}"
echo ""

echo -e "${YELLOW}Stopping Guardian background service...${NC}"

# Unload user or system launchd daemon
launchctl unload "$HOME/Library/LaunchAgents/com.guardian.laptopdefense.plist" 2>/dev/null || true
launchctl unload "/Library/LaunchDaemons/com.guardian.laptopdefense.plist" 2>/dev/null || true

# Kill any node process listening on port 3000
if command -v lsof >/dev/null 2>&1; then
    PIDS=$(lsof -ti :3000 2>/dev/null || true)
    if [ -n "$PIDS" ]; then
        echo "Stopping active process on port 3000 (PID: $PIDS)..."
        kill -9 $PIDS 2>/dev/null || true
    fi
fi

# Remove launchd plists
rm -f "$HOME/Library/LaunchAgents/com.guardian.laptopdefense.plist"
rm -f "/Library/LaunchDaemons/com.guardian.laptopdefense.plist"

# Remove application bundle and installed files
rm -rf "$HOME/Applications/Guardian.app"
rm -rf "/Applications/Guardian.app"
rm -rf "$HOME/Applications/Guardian"
rm -rf "/Applications/Guardian"

echo ""
echo -e "${GREEN}[SUCCESS] Guardian has been cleanly uninstalled from your Mac.${NC}"
echo ""
