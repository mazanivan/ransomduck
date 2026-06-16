#!/usr/bin/env bash
# Uninstall RansomDuck tray GUI for the current user.

set -euo pipefail

BIN_NAME="ransomduck-tray"
ICON_NAME="ransomduck.png"
DESKTOP_NAME="com.ransomduck.tray.desktop"

INSTALL_BIN_DIR="${HOME}/.local/bin"
INSTALL_APPS_DIR="${HOME}/.local/share/applications"
INSTALL_ICONS_DIR="${HOME}/.local/share/icons/hicolor/128x128/apps"

echo "Uninstalling RansomDuck..."

rm -f "${INSTALL_BIN_DIR}/${BIN_NAME}"
rm -f "${INSTALL_APPS_DIR}/${DESKTOP_NAME}"
rm -f "${INSTALL_ICONS_DIR}/${ICON_NAME}"

if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "${INSTALL_APPS_DIR}" || true
fi

echo "RansomDuck uninstalled."
