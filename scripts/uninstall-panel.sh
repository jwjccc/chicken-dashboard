#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/server-probe-monitor"
SERVICE_NAME="server-probe-monitor.service"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"

if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E "$0" "$@"
  fi
  echo "Please run as root, or install sudo." >&2
  exit 1
fi

[[ "$INSTALL_DIR" == "/opt/server-probe-monitor" ]] || exit 1
[[ "$SERVICE_FILE" == "/etc/systemd/system/server-probe-monitor.service" ]] || exit 1

if [[ -t 0 && "${PROBE_UNINSTALL_ASSUME_YES:-}" != "1" ]]; then
  echo "This will permanently remove the Server Probe Monitor panel, its service, configuration, and monitoring data."
  read -r -p "Type DELETE to continue: " answer
  [[ "$answer" == "DELETE" ]] || { echo "Aborted."; exit 1; }
fi

systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
rm -f -- "$SERVICE_FILE"
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true

# The fixed path guard above ensures this cannot expand to an arbitrary directory.
rm -rf -- "$INSTALL_DIR"

echo "Server Probe Monitor panel and its data were removed."
echo "The server-probe-agent service, if installed separately, was not changed."
