#!/usr/bin/env bash
# =====================================================================
# GUARDIAN - macOS Release Packager (Bash)
# Builds dist/Guardian-v1.0.0-macOS.tar.gz and dist/Guardian-v1.0.0-macOS.zip
# =====================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$PROJECT_ROOT/dist"
STAGING_DIR="$DIST_DIR/Guardian-macOS"
ZIP_FILE="$DIST_DIR/Guardian-v1.0.0-macOS.zip"
TAR_FILE="$DIST_DIR/Guardian-v1.0.0-macOS.tar.gz"

echo "Building Guardian macOS release..."

rm -rf "$STAGING_DIR" "$ZIP_FILE" "$TAR_FILE"
mkdir -p "$STAGING_DIR"

cp -R "$PROJECT_ROOT/background" "$STAGING_DIR/"
cp -R "$PROJECT_ROOT/public" "$STAGING_DIR/"
if [ -d "$PROJECT_ROOT/node_modules" ]; then
    cp -R "$PROJECT_ROOT/node_modules" "$STAGING_DIR/"
fi
cp -R "$PROJECT_ROOT/installer" "$STAGING_DIR/"
cp "$PROJECT_ROOT/package.json" "$STAGING_DIR/"
cp "$PROJECT_ROOT/.env.example" "$STAGING_DIR/"
cp "$PROJECT_ROOT/SETUP_GUIDE_MAC.md" "$STAGING_DIR/"

cp "$PROJECT_ROOT/installer/Install-Guardian.command" "$STAGING_DIR/"
cp "$PROJECT_ROOT/installer/Launch-Guardian-App.command" "$STAGING_DIR/"
cp "$PROJECT_ROOT/installer/Uninstall-Guardian.command" "$STAGING_DIR/"
cp "$PROJECT_ROOT/installer/install-mac.sh" "$STAGING_DIR/install.sh"
cp "$PROJECT_ROOT/installer/uninstall-mac.sh" "$STAGING_DIR/uninstall.sh"

chmod +x "$STAGING_DIR"/*.command "$STAGING_DIR"/*.sh "$STAGING_DIR"/installer/*.sh 2>/dev/null || true
mkdir -p "$STAGING_DIR/data"

tar -czf "$TAR_FILE" -C "$DIST_DIR" "Guardian-macOS"
cd "$STAGING_DIR" && zip -r -q "$ZIP_FILE" .

echo "Packages generated successfully:"
echo " - $TAR_FILE"
echo " - $ZIP_FILE"
