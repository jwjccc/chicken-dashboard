#!/usr/bin/env bash
# The hub prepends PANEL_ID, MATCH_KEYS, ACTIVE_KEYS and AGENT_ACTION.
set -Eeuo pipefail
umask 077
OPT_ROOT=/opt
ETC_ROOT=/etc
RUN_ROOT=/run
[[ ${PANEL_ID:-} =~ ^pnl-[a-f0-9]{32}$ ]] || { echo 'Missing or invalid panel identity' >&2; exit 1; }
[[ ${PROBE_PANEL_ID:-$PANEL_ID} == "$PANEL_ID" ]] || { echo 'Panel identity mismatch; nothing changed' >&2; exit 1; }
[[ ${AGENT_ACTION:-} == install || ${AGENT_ACTION:-} == uninstall ]] || exit 1
if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null || { echo 'Please run this command as root' >&2; exit 1; }
  exec sudo -E bash "$0" "$@"
fi
command -v systemctl >/dev/null || { echo 'systemd is required; nothing changed' >&2; exit 1; }
command -v flock >/dev/null || { echo 'flock (util-linux) is required; nothing changed' >&2; exit 1; }
exec 9>"$RUN_ROOT/server-probe-agent-$PANEL_ID.lock"
flock -w 60 9 || { echo 'Another operation for this panel is running' >&2; exit 1; }

HUB_URL="${PROBE_HUB_URL:-${HUB_URL:-}}"
AGENT_TOKEN="${PROBE_AGENT_TOKEN:-${AGENT_TOKEN:-}}"
SERVER_ID="${PROBE_SERVER_ID:-${SERVER_ID:-$(hostname)}}"
SERVER_NAME="${PROBE_SERVER_NAME:-${SERVER_NAME:-$(hostname)}}"
SERVER_LOCATION="${PROBE_SERVER_LOCATION:-${SERVER_LOCATION:-}}"
INTERVAL="${PROBE_INTERVAL:-${INTERVAL:-2}}"
CONNECTIVITY_INTERVAL="${PROBE_CONNECTIVITY_INTERVAL:-${CONNECTIVITY_INTERVAL:-60}}"
SERVICE_NAME="server-probe-agent-$PANEL_ID.service"
INSTALL_DIR="$OPT_ROOT/${SERVICE_NAME%.service}"
ENV_FILE="$ETC_ROOT/$SERVICE_NAME.env"
SERVICE_FILE="$ETC_ROOT/systemd/system/$SERVICE_NAME"

# Parse only literal assignments. Never source/eval an existing env file.
read_value() {
  local file=$1 key=$2 line value char result=''
  REPLY=''
  while IFS= read -r line || [[ -n $line ]]; do
    [[ $line == "$key="* ]] || continue
    value=${line#*=}
    if [[ $value == \$\'*\' ]]; then
      value=${value:2:${#value}-3}
      value=${value//\\\'/\'}
      printf -v REPLY '%b' "$value"
      return 0
    fi
    if [[ $value == \'*\' ]]; then REPLY=${value:1:${#value}-2}; return 0; fi
    if [[ $value == \"*\" ]]; then value=${value:1:${#value}-2}; fi
    # Agent IDs/tokens use literal characters; support Bash %q and systemd escapes.
    while [[ -n $value ]]; do
      char=${value:0:1}; value=${value:1}
      if [[ $char == \\ && -n $value ]]; then char=${value:0:1}; value=${value:1}; fi
      result+=$char
    done
    REPLY=$result
    return 0
  done < "$file"
}
fingerprint() { printf '%s\n%s' "$1" "$2" | sha256sum | cut -d' ' -f1; }
has_key() { [[ " $1 " == *" $2 "* ]]; }
unit_paths() {
  local unit=$1
  [[ $unit =~ ^server-probe-agent(-([a-f0-9]{12}|pnl-[a-f0-9]{32}))?\.service$ ]] || return 1
  UNIT_DIR="$OPT_ROOT/${unit%.service}"
  UNIT_SERVICE="$ETC_ROOT/systemd/system/$unit"
  UNIT_ENV="$ETC_ROOT/$unit.env"
  [[ $unit != server-probe-agent.service ]] || UNIT_ENV="$ETC_ROOT/server-probe-agent.env"
  [[ ! -L $UNIT_DIR && ! -L $UNIT_ENV && ! -L $UNIT_SERVICE ]] || { echo "Refusing symlinked agent files: $unit" >&2; return 1; }
}
declare -a MATCHED=()
reuse_file='' reuse_priority=-1
shopt -s nullglob
for file in "$ETC_ROOT"/server-probe-agent-*.service.env "$ETC_ROOT/server-probe-agent.env"; do
  [[ -f $file && ! -L $file ]] || continue
  unit=${file##*/}; unit=${unit%.env}
  [[ $unit != server-probe-agent ]] || unit=server-probe-agent.service
  [[ $unit =~ ^server-probe-agent(-([a-f0-9]{12}|pnl-[a-f0-9]{32}))?\.service$ ]] || continue
  read_value "$file" PANEL_ID; stored_panel=$REPLY
  read_value "$file" AGENT_TOKEN; stored_token=$REPLY
  read_value "$file" SERVER_ID; stored_server=$REPLY
  key=$(fingerprint "$stored_server" "$stored_token")
  if [[ -n $stored_panel ]]; then
    [[ $stored_panel == "$PANEL_ID" ]] || continue
  else
    [[ -n $stored_token && -n $stored_server ]] && has_key "$MATCH_KEYS" "$key" || continue
  fi
  unit_paths "$unit"
  MATCHED+=("$unit")
  if has_key "$ACTIVE_KEYS" "$key"; then
    priority=$(stat -c %Y "$file")
    [[ $unit != "$SERVICE_NAME" ]] || priority=9223372036854775806
    if (( priority > reuse_priority )); then reuse_priority=$priority; reuse_file=$file; fi
  fi
done

# A saved marker also identifies an interrupted install whose env file is missing.
if [[ ! -e $ENV_FILE && -f $INSTALL_DIR/panel-id && ! -L $INSTALL_DIR/panel-id ]] && [[ $(cat "$INSTALL_DIR/panel-id") == "$PANEL_ID" ]]; then
  unit_paths "$SERVICE_NAME"
  if [[ " ${MATCHED[*]} " != *" $SERVICE_NAME "* ]]; then MATCHED+=("$SERVICE_NAME"); fi
fi

stop_unit() {
  local unit=$1
  unit_paths "$unit"
  if ! systemctl stop "$unit"; then
    if systemctl is-active --quiet "$unit"; then echo "Could not stop $unit; files retained" >&2; return 1; fi
  fi
  systemctl disable "$unit" >/dev/null 2>&1 || true
  local pattern="$OPT_ROOT/${unit%.service}"
  # Exact executable paths only; no broad process-name matching across panels.
  pkill -f "^(node|/[^ ]*/node) $pattern/probe-node\.(cjs|js)$" 2>/dev/null || true
  pkill -f "^(bash|/bin/bash|sh|/bin/sh) $pattern/probe\.sh$" 2>/dev/null || true
}
remove_unit_files() {
  local unit=$1
  unit_paths "$unit"
  rm -f -- "$UNIT_SERVICE" "$UNIT_ENV"
  rm -rf -- "$UNIT_DIR" "$RUN_ROOT/${unit%.service}"
  systemctl reset-failed "$unit" 2>/dev/null || true
}
if [[ $AGENT_ACTION == uninstall ]]; then
  if ((${#MATCHED[@]} == 0)); then echo 'No agent belonging to this panel was found; nothing removed.'; exit 0; fi
  for unit in "${MATCHED[@]}"; do stop_unit "$unit"; remove_unit_files "$unit"; done
  systemctl daemon-reload
  printf 'Uninstalled %s agent instance(s) belonging to panel %s.\n' "${#MATCHED[@]}" "$PANEL_ID"
  exit 0
fi

[[ -n $HUB_URL && -n $AGENT_TOKEN && -n $SERVER_ID ]] || { echo 'Hub URL, token and server ID are required' >&2; exit 1; }
# The global install button means update an existing registered agent on this host.
# A command copied from a specific server still applies that explicit identity.
if [[ ${PROBE_REUSE_EXISTING:-0} == 1 && -n $reuse_file ]]; then
  for field in AGENT_TOKEN SERVER_ID SERVER_NAME SERVER_LOCATION; do
    read_value "$reuse_file" "$field"
    [[ -z $REPLY && $field != SERVER_LOCATION ]] || printf -v "$field" '%s' "$REPLY"
  done
  echo 'Updating the existing registered agent for this panel.'
fi
for value in "$HUB_URL" "$AGENT_TOKEN" "$SERVER_ID" "$SERVER_NAME" "$SERVER_LOCATION"; do
  [[ $value != *$'\n'* && $value != *$'\r'* ]] || { echo 'Values must not contain newlines' >&2; exit 1; }
done
[[ $INTERVAL =~ ^[0-9]+$ && $CONNECTIVITY_INTERVAL =~ ^[0-9]+$ ]] || { echo 'Intervals must be integers' >&2; exit 1; }
unit_paths "$SERVICE_NAME"
if [[ -e $INSTALL_DIR || -e $ENV_FILE || -e $SERVICE_FILE ]]; then
  [[ " ${MATCHED[*]} " == *" $SERVICE_NAME "* ]] || { echo 'Existing files have unverified ownership; nothing changed' >&2; exit 1; }
fi
if ! command -v node >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update && apt-get install -y nodejs
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache nodejs
  elif command -v dnf >/dev/null 2>&1; then dnf install -y nodejs
  elif command -v yum >/dev/null 2>&1; then yum install -y nodejs
  fi
fi
tmp_dir=$(mktemp -d "$OPT_ROOT/.server-probe-agent.install.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
curl --fail --silent --show-error --connect-timeout 10 --max-time 60 "${HUB_URL%/}/api/agent/probe.sh" -o "$tmp_dir/probe.sh"
curl --fail --silent --show-error --connect-timeout 10 --max-time 60 "${HUB_URL%/}/api/agent/probe-node.cjs" -o "$tmp_dir/probe-node.cjs"
bash -n "$tmp_dir/probe.sh"
if command -v node >/dev/null; then node --check "$tmp_dir/probe-node.cjs"; fi

STATE_DIR="$RUN_ROOT/${SERVICE_NAME%.service}"
{
  for field in PANEL_ID HUB_URL AGENT_TOKEN SERVER_ID SERVER_NAME SERVER_LOCATION INTERVAL CONNECTIVITY_INTERVAL STATE_DIR; do
    # systemd EnvironmentFile uses quoted literals, not shell expansion.
    value=${!field}; value=${value//\\/\\\\}; value=${value//\"/\\\"}
    printf '%s="%s"\n' "$field" "$value"
  done
} > "$tmp_dir/agent.env"
cat > "$tmp_dir/agent.service" <<SERVICE
[Unit]
Description=Server Probe Monitor Agent ($PANEL_ID)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
EnvironmentFile=$ENV_FILE
Environment="CONNECTIONS_TTL_SECONDS=2"
Environment="NODE_OPTIONS=--max-old-space-size=48 --max-semi-space-size=2"
ExecStart=/bin/sh -c 'if command -v node >/dev/null 2>&1 && [ -f "$INSTALL_DIR/probe-node.cjs" ]; then exec node "$INSTALL_DIR/probe-node.cjs"; else exec "$INSTALL_DIR/probe.sh"; fi'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

declare -a WAS_ACTIVE=() WAS_ENABLED=()
for unit in "${MATCHED[@]}"; do
  if systemctl is-active --quiet "$unit"; then WAS_ACTIVE+=("$unit"); fi
  if systemctl is-enabled --quiet "$unit"; then WAS_ENABLED+=("$unit"); fi
done
[[ ! -d $INSTALL_DIR ]] || cp -a -- "$INSTALL_DIR" "$tmp_dir/previous-dir"
[[ ! -f $ENV_FILE ]] || cp -a -- "$ENV_FILE" "$tmp_dir/previous-env"
[[ ! -f $SERVICE_FILE ]] || cp -a -- "$SERVICE_FILE" "$tmp_dir/previous-service"
rollback() {
  trap - ERR
  set +e
  restore_failed=0
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -rf -- "$INSTALL_DIR"
  rm -f -- "$ENV_FILE" "$SERVICE_FILE"
  if [[ -d $tmp_dir/previous-dir ]]; then cp -a -- "$tmp_dir/previous-dir" "$INSTALL_DIR" || restore_failed=1; fi
  if [[ -f $tmp_dir/previous-env ]]; then cp -a -- "$tmp_dir/previous-env" "$ENV_FILE" || restore_failed=1; fi
  if [[ -f $tmp_dir/previous-service ]]; then cp -a -- "$tmp_dir/previous-service" "$SERVICE_FILE" || restore_failed=1; fi
  systemctl daemon-reload || restore_failed=1
  for unit in "${WAS_ENABLED[@]}"; do systemctl enable "$unit" || restore_failed=1; done
  for unit in "${WAS_ACTIVE[@]}"; do systemctl restart "$unit" || restore_failed=1; done
  if ((restore_failed)); then
    trap - EXIT
    printf 'Update failed and recovery needs attention; backup retained at %s\n' "$tmp_dir" >&2
    exit 1
  fi
  echo 'Update failed; previous agent configuration restored.' >&2
  exit 1
}
trap rollback ERR
for unit in "${MATCHED[@]}"; do stop_unit "$unit"; done
rm -rf -- "$STATE_DIR"
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$tmp_dir/probe.sh" "$INSTALL_DIR/probe.sh"
install -m 0755 "$tmp_dir/probe-node.cjs" "$INSTALL_DIR/probe-node.cjs"
rm -f -- "$INSTALL_DIR/probe-node.js"
printf '%s\n' "$PANEL_ID" > "$INSTALL_DIR/panel-id"
install -m 0600 "$tmp_dir/agent.env" "$ENV_FILE"
install -m 0644 "$tmp_dir/agent.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
systemctl is-active --quiet "$SERVICE_NAME"
trap - ERR
for unit in "${MATCHED[@]}"; do [[ $unit == "$SERVICE_NAME" ]] || remove_unit_files "$unit"; done
systemctl daemon-reload
printf 'Installed/updated one agent for panel %s; previous matching instances retired.\n' "$PANEL_ID"
