#!/usr/bin/env bash
# Install RansomDuck tray GUI for the current user.
# This script copies the release binary to ~/.local/bin and registers a
# .desktop entry so the app appears in the system application menu.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="ransomduck-tray"
ICON_NAME="ransomduck.png"
DESKTOP_NAME="com.ransomduck.tray.desktop"

SOURCE_BIN="${SCRIPT_DIR}/target/release/${BIN_NAME}"
SOURCE_ICON="${SCRIPT_DIR}/gui/tauri-app/src-tauri/icons/icon.png"

INSTALL_BIN_DIR="${HOME}/.local/bin"
INSTALL_APPS_DIR="${HOME}/.local/share/applications"
INSTALL_ICONS_DIR="${HOME}/.local/share/icons/hicolor/128x128/apps"

echo "Installing RansomDuck..."

if [[ ! -f "${SOURCE_BIN}" ]]; then
    echo "ERROR: Release binary not found: ${SOURCE_BIN}"
    echo "Build it first with:"
    echo "  cd gui/tauri-app && npm run tauri build"
    exit 1
fi

mkdir -p "${INSTALL_BIN_DIR}"
mkdir -p "${INSTALL_APPS_DIR}"
mkdir -p "${INSTALL_ICONS_DIR}"

rm -f "${INSTALL_BIN_DIR}/${BIN_NAME}"
cp "${SOURCE_BIN}" "${INSTALL_BIN_DIR}/${BIN_NAME}"
chmod +x "${INSTALL_BIN_DIR}/${BIN_NAME}"

if [[ -f "${SOURCE_ICON}" ]]; then
    cp "${SOURCE_ICON}" "${INSTALL_ICONS_DIR}/${ICON_NAME}"
else
    echo "WARNING: Icon not found at ${SOURCE_ICON}; the menu entry will be generic."
fi

cat > "${INSTALL_APPS_DIR}/${DESKTOP_NAME}" <<EOF
[Desktop Entry]
Name=RansomDuck
Comment=Local anti-ransomware canary guardian
Exec=${INSTALL_BIN_DIR}/${BIN_NAME}
Icon=${INSTALL_ICONS_DIR}/${ICON_NAME}
Type=Application
Terminal=false
Categories=System;Security;Utility;
Keywords=ransomware;security;canary;protection;
EOF

chmod +x "${INSTALL_APPS_DIR}/${DESKTOP_NAME}"

# Refresh icon cache and desktop database if available.
if command -v gtk-update-icon-cache &> /dev/null; then
    gtk-update-icon-cache -f -t "${HOME}/.local/share/icons/hicolor" || true
fi

if command -v xdg-desktop-menu &> /dev/null; then
    xdg-desktop-menu forceupdate || true
fi

if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "${INSTALL_APPS_DIR}" || true
fi

echo "RansomDuck installed successfully."
echo "  Binary: ${INSTALL_BIN_DIR}/${BIN_NAME}"
echo "  Menu entry: ${INSTALL_APPS_DIR}/${DESKTOP_NAME}"
echo ""
echo "You can now:"
echo "  - Launch RansomDuck from your application menu, or"
echo "  - Run: ${INSTALL_BIN_DIR}/${BIN_NAME}"
