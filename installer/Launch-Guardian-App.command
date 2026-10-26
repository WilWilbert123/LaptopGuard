#!/usr/bin/env bash
# Double-click launcher for macOS Finder
cd "$(dirname "$0")"

# Start background service if not active
if ! curl -s -m 1 http://127.0.0.1:3000/api/status >/dev/null 2>&1; then
    APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ ! -f "$APP_DIR/background/server.js" ] && [ -f "$APP_DIR/../background/server.js" ]; then
        APP_DIR="$(cd "$APP_DIR/.." && pwd)"
    fi
    node "$APP_DIR/background/server.js" >/dev/null 2>&1 &
    sleep 1.5
fi

# Launch in Standalone App Window Mode
if [ -d "/Applications/Microsoft Edge.app" ]; then
    open -na "Microsoft Edge" --args --app=http://127.0.0.1:3000 --app-id=GuardianSecurity --window-size=1360,860
elif [ -d "/Applications/Google Chrome.app" ]; then
    open -na "Google Chrome" --args --app=http://127.0.0.1:3000 --app-id=GuardianSecurity --window-size=1360,860
elif [ -d "/Applications/Brave Browser.app" ]; then
    open -na "Brave Browser" --args --app=http://127.0.0.1:3000 --app-id=GuardianSecurity --window-size=1360,860
else
    open "http://127.0.0.1:3000"
fi
