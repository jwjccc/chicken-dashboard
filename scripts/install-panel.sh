#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${PROBE_REPO_URL:-https://github.com/jwjccc/chicken-dashboard.git}"
REF="${PROBE_REF:-main}"
INSTALL_DIR="${PROBE_PANEL_DIR:-/opt/server-probe-monitor}"
SERVICE_NAME="${PROBE_PANEL_SERVICE:-server-probe-monitor}"
[[ "$SERVICE_NAME" == "server-probe-monitor" ]] || { echo "PROBE_PANEL_SERVICE must remain server-probe-monitor" >&2; exit 1; }
[[ "$INSTALL_DIR" == "/opt/server-probe-monitor" ]] || { echo "PROBE_PANEL_DIR must remain /opt/server-probe-monitor" >&2; exit 1; }
PORT="${PROBE_PORT:-8080}"

if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E env \
      PROBE_REPO_URL="$REPO_URL" \
      PROBE_REF="$REF" \
      PROBE_PANEL_DIR="$INSTALL_DIR" \
      PROBE_PANEL_SERVICE="$SERVICE_NAME" \
      PROBE_PORT="$PORT" \
      "$0" "$@"
  fi
  echo "Please run as root, or install sudo." >&2
  exit 1
fi

ensure_dependencies() {
  if command -v git >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl git nodejs
  fi

  command -v git >/dev/null 2>&1 || {
    echo "git is required. Install it first and rerun this script." >&2
    exit 1
  }
  command -v node >/dev/null 2>&1 || {
    echo "node is required. Install Node.js 22.5+ first and rerun this script." >&2
    exit 1
  }
}

ensure_dependencies
NODE_VERSION="$(node -p 'process.versions.node')"
NODE_MAJOR="${NODE_VERSION%%.*}"
NODE_MINOR="${NODE_VERSION#*.}"; NODE_MINOR="${NODE_MINOR%%.*}"
if (( NODE_MAJOR < 22 )) || (( NODE_MAJOR == 22 && NODE_MINOR < 5 )); then
  echo "Node.js 22.5+ is required (found ${NODE_VERSION}); refusing to install a service that cannot start." >&2
  exit 1
fi

mkdir -p "$(dirname "$INSTALL_DIR")"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  git -C "$INSTALL_DIR" fetch --depth 1 origin "$REF"
  git -C "$INSTALL_DIR" checkout -f FETCH_HEAD
else
  if [[ -e "$INSTALL_DIR" ]]; then
    if [[ -t 0 ]]; then
      read -r -p "Install directory exists and is not a Git checkout; replace it? [y/N] " answer
      [[ "$answer" == "y" || "$answer" == "Y" ]] || { echo "Aborted." >&2; exit 1; }
    else
      echo "Refusing to replace existing non-Git directory without confirmation." >&2
      exit 1
    fi
    mv -- "$INSTALL_DIR" "${INSTALL_DIR}.backup.$(date +%s)"
  fi
  git clone --depth 1 --branch "$REF" "$REPO_URL" "$INSTALL_DIR"
fi

mkdir -p "$INSTALL_DIR/data"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<SERVICE
[Unit]
Description=Server Probe Monitor Hub
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
Environment=PROBE_PORT=$PORT
Environment=MAX_CONNECTIVITY_HISTORY_POINTS=100000
Environment=HISTORY_SAMPLE_INTERVAL_MS=1000
Environment="NODE_OPTIONS=--max-old-space-size=256 --max-semi-space-size=8"
ExecStart=/usr/bin/env node hub/server.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME.service"
sleep 1
if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
  echo "Panel failed to start; recent logs:" >&2
  journalctl -u "$SERVICE_NAME.service" -n 80 --no-pager >&2
  exit 1
fi
systemctl status "$SERVICE_NAME.service" --no-pager

echo
LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
LOCAL_IP="${LOCAL_IP:-SERVER_IP}"
echo "Server Probe Monitor installed."
echo "登录地址: http://${LOCAL_IP}:${PORT}"
echo "默认登录用户名/密码: admin / admin"
echo "Change the admin username/password immediately after first login."
echo "Optional backgrounds, connectivity checks, and basic features stay disabled until configured in the admin backend."
echo "The panel port and Agent response URL are initialized automatically."
