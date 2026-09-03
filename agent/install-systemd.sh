#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo HUB_URL=... AGENT_TOKEN=... SERVER_ID=... bash agent/install-systemd.sh" >&2
  exit 1
fi

HUB_URL="${HUB_URL:?HUB_URL is required, example: https://monitor.example.com}"
AGENT_TOKEN="${AGENT_TOKEN:?AGENT_TOKEN is required}"
SERVER_ID="${SERVER_ID:-$(hostname)}"
SERVER_NAME="${SERVER_NAME:-$(hostname)}"
SERVER_LOCATION="${SERVER_LOCATION:-}"
INTERVAL="${INTERVAL:-2}"
CONNECTIVITY_INTERVAL="${CONNECTIVITY_INTERVAL:-60}"
INSTALL_DIR="/opt/server-probe-agent"
SERVICE_FILE="/etc/systemd/system/server-probe-agent.service"
ENV_FILE="/etc/server-probe-agent.env"
SOURCE_DIR=$(cd -- "$(dirname -- "$0")" && pwd)

reject_unsafe_value() {
  local name="$1" value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    echo "$name must not contain newlines" >&2
    exit 1
  fi
  # Bash cannot represent NUL bytes; an inherited value containing one is truncated by the OS.
}
env_quote() { printf '"%s"' "${1//\\/\\\\}" | sed 's/"/\\"/g; s/^\\"/"/; s/\\"$/"/'; }
for name in HUB_URL AGENT_TOKEN SERVER_ID SERVER_NAME SERVER_LOCATION INTERVAL CONNECTIVITY_INTERVAL; do
  reject_unsafe_value "$name" "${!name}"
done
[[ "$INTERVAL" =~ ^[0-9]+$ && "$CONNECTIVITY_INTERVAL" =~ ^[0-9]+$ ]] || { echo "Intervals must be integers" >&2; exit 1; }

if ! command -v node >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y nodejs
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache nodejs
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nodejs
  elif command -v yum >/dev/null 2>&1; then
    yum install -y nodejs
  fi
fi

umask 077
tmp_dir=$(mktemp -d /opt/.server-probe-agent.install.XXXXXX)
trap 'rm -rf -- "$tmp_dir"' EXIT
install -m 0755 "$SOURCE_DIR/probe.sh" "$tmp_dir/probe.sh"
if [[ -f "$SOURCE_DIR/probe-node.cjs" ]]; then
  install -m 0755 "$SOURCE_DIR/probe-node.cjs" "$tmp_dir/probe-node.cjs"
fi
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$tmp_dir/probe.sh" "$INSTALL_DIR/probe.sh.new"
mv -f "$INSTALL_DIR/probe.sh.new" "$INSTALL_DIR/probe.sh"
if [[ -f "$tmp_dir/probe-node.cjs" ]]; then
  install -m 0755 "$tmp_dir/probe-node.cjs" "$INSTALL_DIR/probe-node.cjs.new"
  mv -f "$INSTALL_DIR/probe-node.cjs.new" "$INSTALL_DIR/probe-node.cjs"
fi
rm -f "$INSTALL_DIR/probe-node.js"

{
  printf 'HUB_URL=%s\n' "$(env_quote "$HUB_URL")"
  printf 'AGENT_TOKEN=%s\n' "$(env_quote "$AGENT_TOKEN")"
  printf 'SERVER_ID=%s\n' "$(env_quote "$SERVER_ID")"
  printf 'SERVER_NAME=%s\n' "$(env_quote "$SERVER_NAME")"
  printf 'SERVER_LOCATION=%s\n' "$(env_quote "$SERVER_LOCATION")"
  printf 'INTERVAL=%s\n' "$(env_quote "$INTERVAL")"
  printf 'CONNECTIVITY_INTERVAL=%s\n' "$(env_quote "$CONNECTIVITY_INTERVAL")"
} > "$ENV_FILE.new"
chmod 0600 "$ENV_FILE.new"
mv -f "$ENV_FILE.new" "$ENV_FILE"

cat > "$SERVICE_FILE.new" <<'SERVICE'
[Unit]
Description=Server Probe Monitor Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/server-probe-agent.env
Environment="CONNECTIONS_TTL_SECONDS=2"
Environment="NODE_OPTIONS=--max-old-space-size=48 --max-semi-space-size=2"
ExecStart=/bin/sh -c 'if command -v node >/dev/null 2>&1 && [ -f /opt/server-probe-agent/probe-node.cjs ]; then exec node /opt/server-probe-agent/probe-node.cjs; else exec /opt/server-probe-agent/probe.sh; fi'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE
chmod 0644 "$SERVICE_FILE.new"
mv -f "$SERVICE_FILE.new" "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable server-probe-agent.service
systemctl restart server-probe-agent.service
systemctl status server-probe-agent.service --no-pager
