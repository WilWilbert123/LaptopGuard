#!/usr/bin/env bash
# Double-click launcher for macOS Finder
cd "$(dirname "$0")"
bash ./installer/install-mac.sh || bash ./install-mac.sh
echo ""
echo "Press [Enter] to exit..."
read -r
