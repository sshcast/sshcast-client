#!/usr/bin/env bash
set -euo pipefail

PLIST_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/io.sshcast.client.plist"
PLIST_DST="${HOME}/Library/LaunchAgents/io.sshcast.client.plist"
BIN_PATH="$(command -v sshcast-tray || echo "/usr/local/bin/sshcast-tray")"

mkdir -p "${HOME}/Library/LaunchAgents"
sed "s|/usr/local/bin/sshcast-tray|${BIN_PATH}|g" "${PLIST_SRC}" > "${PLIST_DST}"

launchctl unload "${PLIST_DST}" 2>/dev/null || true
launchctl load -w "${PLIST_DST}"

echo "Installed and started macOS LaunchAgent: ${PLIST_DST} (binary: ${BIN_PATH})"
