#!/usr/bin/env bash
set -euo pipefail

PLIST_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/net.sshcast.client.plist"
PLIST_DST="${HOME}/Library/LaunchAgents/net.sshcast.client.plist"
LEGACY_PLIST="${HOME}/Library/LaunchAgents/io.sshcast.client.plist"
BIN_PATH="$(command -v sshcast-tray || echo "/usr/local/bin/sshcast-tray")"

mkdir -p "${HOME}/Library/LaunchAgents"
if [ -f "${LEGACY_PLIST}" ]; then
  launchctl unload "${LEGACY_PLIST}" 2>/dev/null || true
  rm -f "${LEGACY_PLIST}"
fi
sed "s|/usr/local/bin/sshcast-tray|${BIN_PATH}|g" "${PLIST_SRC}" > "${PLIST_DST}"

launchctl unload "${PLIST_DST}" 2>/dev/null || true
launchctl load -w "${PLIST_DST}"

echo "Installed and started macOS LaunchAgent: ${PLIST_DST} (binary: ${BIN_PATH})"
