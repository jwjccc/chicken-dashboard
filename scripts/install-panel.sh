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
systemctl enable "$SERVICE_NAME.service"
# Restart also loads updated code and unit settings when the service is active.
systemctl restart "$SERVICE_NAME.service"
sleep 1
if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
  echo "Panel failed to start; recent logs:" >&2
  journalctl -u "$SERVICE_NAME.service" -n 80 --no-pager >&2
  exit 1
fi
systemctl status "$SERVICE_NAME.service" --no-pager

is_login_ipv4() {
  local address="$1" octet
  local -a octets
  [[ "$address" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a octets <<< "$address"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
  (( 10#${octets[0]} > 0 && 10#${octets[0]} < 224 && 10#${octets[0]} != 127 )) || return 1
  [[ "${octets[0]}.${octets[1]}" != '169.254' ]]
}

is_public_login_ipv4() {
  is_login_ipv4 "$1" || return 1
  local -a octets
  local first second
  IFS=. read -r -a octets <<< "$1"
  first=$((10#${octets[0]})); second=$((10#${octets[1]}))
  (( first != 10 )) && ! (( first == 172 && second >= 16 && second <= 31 )) &&
    ! (( first == 192 && second == 168 )) && ! (( first == 100 && second >= 64 && second <= 127 ))
}

detect_login_ipv4() {
  local endpoint address candidates fallback=''
  # IPv4-only discovery also works when the NIC has a private address behind NAT.
  # Bypass proxy environment variables so the result is this server's egress IP.
  if command -v curl >/dev/null 2>&1; then
    for endpoint in https://api.ipify.org https://ipv4.icanhazip.com; do
      address="$(curl -4 --noproxy '*' -fsS --connect-timeout 2 --max-time 3 --max-filesize 64 "$endpoint" 2>/dev/null || true)"
      address="${address//[[:space:]]/}"
      if is_public_login_ipv4 "$address"; then printf '%s' "$address"; return 0; fi
    done
  fi
  # Prefer the default route over Docker/secondary NIC addresses if offline.
  candidates="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1);exit}}' || true) $(hostname -I 2>/dev/null || true)"
  for address in $candidates; do
    if is_public_login_ipv4 "$address"; then printf '%s' "$address"; return 0; fi
    if [[ -z "$fallback" ]] && is_login_ipv4 "$address"; then fallback="$address"; fi
  done
  [[ -n "$fallback" ]] || return 1
  printf '%s' "$fallback"
}

echo
echo "Server Probe Monitor installed."
LOGIN_IPV4="$(detect_login_ipv4 || true)"
if [[ -n "$LOGIN_IPV4" ]]; then
  echo "登录地址: http://${LOGIN_IPV4}:${PORT}"
  if ! is_public_login_ipv4 "$LOGIN_IPV4"; then
    echo "公网 IPv4 查询未成功，以上为本机内网地址；外网访问请使用服务器公网 IPv4:${PORT}。"
  fi
else
  echo "未能自动识别 IPv4，请使用服务器公网 IPv4 访问端口 ${PORT}。"
fi
echo "默认登录用户名/密码: admin / admin"
echo "Change the admin username/password immediately after first login."
echo "Optional backgrounds, connectivity checks, and basic features stay disabled until configured in the admin backend."
echo "The panel port and Agent response URL are initialized automatically."
