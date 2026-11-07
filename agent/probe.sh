#!/usr/bin/env bash
set -euo pipefail

AGENT_PROBE_VERSION="20261105-shell-target-retry-v4"

HUB_URL="${HUB_URL:-http://127.0.0.1:8080}"
AGENT_TOKEN="${AGENT_TOKEN:-}"
SERVER_ID="${SERVER_ID:-$(hostname)}"
SERVER_NAME="${SERVER_NAME:-$(hostname)}"
SERVER_LOCATION="${SERVER_LOCATION:-}"
INTERVAL="${INTERVAL:-2}"
CONNECTIVITY_INTERVAL=5 # task polling; target intervals are controlled by the hub
INSTANCE_ID="${PANEL_ID:-$(printf '%s' "$HUB_URL" | sha256sum | cut -c1-12)}"
STATE_DIR="${STATE_DIR:-/run/server-probe-agent-${INSTANCE_ID}}"
umask 077
if [[ $EUID -ne 0 ]]; then
  echo "probe.sh must run as root so state stays in a root-only directory" >&2
  exit 1
fi
install -d -m 0700 -o root -g root "$STATE_DIR"
STATE_FILE="$STATE_DIR/net.state"
CPU_STATE_FILE="$STATE_DIR/cpu.state"
IP_META_FILE="$STATE_DIR/ip.json"
PUBLIC_IPV4_FILE="$STATE_DIR/public-ipv4"
PUBLIC_IPV6_FILE="$STATE_DIR/public-ipv6"
IP_META_TTL="${IP_META_TTL:-3600}"
CONNECTIVITY_FILE="$STATE_DIR/connectivity.tsv"
CONNECTIVITY_LAST_FILE="$STATE_DIR/connectivity.last"
CONNECTIVITY_ERROR_FILE="$STATE_DIR/connectivity.err"
CONNECTIVITY_RESULT_FILE="$STATE_DIR/connectivity-result.json"
CONNECTIVITY_ERROR=""
CONNECTIVITY_COUNT="0"

command_exists() { command -v "$1" >/dev/null 2>&1; }
json_escape() { sed 's/\\/\\\\/g; s/"/\\"/g' <<<"$1" | tr -d '\n'; }

if [[ -z "$AGENT_TOKEN" ]]; then
  echo "AGENT_TOKEN is required. Generate a per-server install command from the admin panel." >&2
  exit 1
fi

json_value() {
  local key="$1"
  sed -nE "s/.*\"${key}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/p" | head -n 1
}

read_cpu_total_idle() {
  awk '/^cpu / { idle=$5+$6; total=0; for (i=2; i<=NF; i++) total+=$i; print total, idle }' /proc/stat
}

cpu_percent() {
  local total idle prev_total prev_idle total_delta idle_delta percent
  read -r total idle < <(read_cpu_total_idle)
  prev_total="$total"
  prev_idle="$idle"
  if [[ -f "$CPU_STATE_FILE" ]]; then
    read -r prev_total prev_idle < "$CPU_STATE_FILE" || { prev_total="$total"; prev_idle="$idle"; }
    [[ "$prev_total" =~ ^[0-9]+$ ]] || prev_total="$total"
    [[ "$prev_idle" =~ ^[0-9]+$ ]] || prev_idle="$idle"
  fi
  total_delta=$((total - prev_total))
  idle_delta=$((idle - prev_idle))
  percent=$(awk -v total="$total_delta" -v idle="$idle_delta" 'BEGIN { if (total <= 0) print 0; else printf "%.2f", (total-idle)*100/total }')
  printf '%s %s\n' "$total" "$idle" > "$CPU_STATE_FILE"
  printf '%s' "$percent"
}

memory_json() {
  awk '
    /^MemTotal:/ { mt=$2*1024 }
    /^MemAvailable:/ { ma=$2*1024 }
    /^SwapTotal:/ { st=$2*1024 }
    /^SwapFree:/ { sf=$2*1024 }
    END {
      mu=mt-ma; sp=st-sf;
      mp=(mt>0 ? mu*100/mt : 0); spp=(st>0 ? sp*100/st : 0);
      printf "\"memory\":{\"total\":%.0f,\"used\":%.0f,\"available\":%.0f,\"percent\":%.2f},\"swap\":{\"total\":%.0f,\"used\":%.0f,\"percent\":%.2f}", mt, mu, ma, mp, st, sp, spp;
    }' /proc/meminfo
}

disk_json() {
  df -B1 / | awk 'NR==2 { total=$2; used=$3; avail=$4; pct=$5; gsub(/%/, "", pct); printf "\"disk\":{\"total\":%.0f,\"used\":%.0f,\"available\":%.0f,\"percent\":%.2f}", total, used, avail, pct }'
}

net_totals() {
  awk -F'[: ]+' 'NR>2 && $2 != "lo" { rx += $3; tx += $11 } END { printf "%.0f %.0f\n", rx, tx }' /proc/net/dev
}

connections_json() {
  local tcp udp
  tcp=$(awk 'NR>1 { count++ } END { print count+0 }' /proc/net/tcp /proc/net/tcp6 2>/dev/null || echo 0)
  udp=$(awk 'NR>1 { count++ } END { print count+0 }' /proc/net/udp /proc/net/udp6 2>/dev/null || echo 0)
  printf '"connections":{"tcp":%d,"udp":%d}' "$tcp" "$udp"
}

fetch_connectivity_checks() {
  command_exists curl || return 1
  CONNECTIVITY_ERROR=""
  if ! curl -fsS --max-time 5 \
    -H "Authorization: Bearer ${AGENT_TOKEN}" \
    "${HUB_URL%/}/api/agent/connectivity?serverId=$(url_encode "$SERVER_ID")" \
    -o "$CONNECTIVITY_FILE" 2>"$CONNECTIVITY_ERROR_FILE"; then
    CONNECTIVITY_ERROR=$(cat "$CONNECTIVITY_ERROR_FILE" 2>/dev/null || echo fetch_failed)
    return 1
  fi
  CONNECTIVITY_COUNT=$(awk -F'\t' 'NF >= 3 { count++ } END { print count+0 }' "$CONNECTIVITY_FILE" 2>/dev/null || echo 0)
}

url_encode() {
  local s="$1" i c out=""
  for (( i=0; i<${#s}; i++ )); do
    c=${s:i:1}
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v out '%s%%%02X' "$out" "'${c}" ;;
    esac
  done
  printf '%s' "$out"
}

tcp_latency_ms() {
  local host="$1" port="$2" start end
  start=$(date +%s%3N 2>/dev/null || date +%s000)
  if timeout 2 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" >/dev/null 2>&1; then
    end=$(date +%s%3N 2>/dev/null || date +%s000)
    echo $((end - start))
    return 0
  fi
  return 1
}

probe_connectivity_target() {
  local id="$1" name="$2" target="$3" attempts="$4" task_at="$5"
  local host="$target" port=80 latency=0 ok=false error=timeout attempt packet_loss=100 result_key tmp now
  if [[ "$target" =~ ^\[([^]]+)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"
  elif [[ "$target" == *:* && "$target" != *:*:* ]]; then
    host="${target%:*}"; port="${target##*:}"
  fi
  [[ "$attempts" =~ ^[1-4]$ ]] || attempts=4
  [[ "$task_at" =~ ^[0-9]+$ ]] || task_at=0
  for ((attempt=1;attempt<=attempts;attempt++)); do
    if latency=$(tcp_latency_ms "$host" "$port") && [[ "$latency" =~ ^[0-9]+$ ]] && ((latency>0)); then
      ok=true; error=""; packet_loss=0; break
    fi
    latency=0
  done
  ((attempt>attempts)) && attempt=$attempts
  now=$(date +%s%3N)
  result_key=$(printf '%s' "$id" | sha256sum | cut -c1-32)
  tmp=$(mktemp "$STATE_DIR/target-results/.result.XXXXXX")
  printf '{"id":"%s","name":"%s","ok":%s,"error":"%s","latencyMs":%s,"packetLossPercent":%s,"checkedAt":%s,"taskAt":%s,"attempts":%s,"final":true}' \
    "$(json_escape "$id")" "$(json_escape "$name")" "$ok" "$error" "$latency" "$packet_loss" "$now" "$task_at" "$attempt" > "$tmp"
  mv -f "$tmp" "$STATE_DIR/target-results/$result_key.json"
}

connectivity_json() {
  local first=1 id name target interval attempts task_at file
  install -d -m 0700 "$STATE_DIR/target-results"
  if fetch_connectivity_checks; then
    while IFS=$'\t' read -r id name target interval attempts task_at; do
      [[ -n "${id:-}" && -n "${target:-}" ]] || continue
      probe_connectivity_target "$id" "$name" "$target" "${attempts:-4}" "${task_at:-0}" &
    done < "$CONNECTIVITY_FILE"
    wait
  fi
  printf '"connectivity":['
  for file in "$STATE_DIR"/target-results/*.json; do
    [[ -f "$file" ]] || continue
    [[ $first -eq 1 ]] || printf ','
    first=0;cat "$file"
  done
  printf ']'
}

connectivity_meta_json() {
  printf '"connectivityMeta":{"count":%d,"error":"%s"}' "${CONNECTIVITY_COUNT:-0}" "$(json_escape "${CONNECTIVITY_ERROR:-}")"
}

connectivity_due() {
  local now last
  now=$(date +%s)
  last=0
  if [[ -f "$CONNECTIVITY_LAST_FILE" ]]; then
    read -r last < "$CONNECTIVITY_LAST_FILE" || last=0
  fi
  [[ -z "${last:-}" ]] && last=0
  (( now - last >= CONNECTIVITY_INTERVAL ))
}

mark_connectivity_checked() {
  date +%s > "$CONNECTIVITY_LAST_FILE"
}

run_connectivity_checks() {
  local tmp
  tmp=$(mktemp "$STATE_DIR/connectivity-result.XXXXXX")
  {
    printf '{'
    connectivity_json; printf ','
    connectivity_meta_json
    printf '}'
  } > "$tmp"
  mv -f "$tmp" "$CONNECTIVITY_RESULT_FILE"
  mark_connectivity_checked
}

connectivity_daemon() {
  while true; do
    run_connectivity_checks || true
    sleep "$CONNECTIVITY_INTERVAL"
  done
}

refresh_ip_meta() {
  local now cached_at tmp detected_ipv4 detected_ipv6
  now=$(date +%s)
  cached_at=0
  if [[ -f "$IP_META_FILE" ]]; then
    cached_at=$(sed -nE 's/.*"cachedAt"[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p' "$IP_META_FILE" | head -n 1)
    cached_at=${cached_at:-0}
  fi
  if (( now - cached_at >= IP_META_TTL )); then
  tmp=$(mktemp "$STATE_DIR/ip.XXXXXX")
  if curl -fsS --max-time 5 https://ipinfo.io/json -o "$tmp"; then
    sed "s/[[:space:]]*}[[:space:]]*$/,\"cachedAt\":${now}}/" "$tmp" > "$IP_META_FILE.new"
    mv -f "$IP_META_FILE.new" "$IP_META_FILE"
    rm -f "$tmp"
  else
    rm -f "$tmp"
  fi
  fi
  # Address discovery runs in its own background worker every minute.
  detected_ipv4=$(fetch_public_ip https://api.ipify.org || true)
  detected_ipv6=$(fetch_public_ip https://api6.ipify.org || true)
  if [[ "$detected_ipv4" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    if [[ "$detected_ipv4" != "$(cat "$PUBLIC_IPV4_FILE" 2>/dev/null || true)" && -f "$IP_META_FILE" ]]; then
      sed -E 's/"cachedAt"[[:space:]]*:[[:space:]]*[0-9]+/"cachedAt":0/' "$IP_META_FILE" > "$IP_META_FILE.new"
      mv -f "$IP_META_FILE.new" "$IP_META_FILE"
    fi
    printf '%s' "$detected_ipv4" > "$PUBLIC_IPV4_FILE.new" && mv -f "$PUBLIC_IPV4_FILE.new" "$PUBLIC_IPV4_FILE"
  fi
  if [[ "$detected_ipv6" =~ ^[a-fA-F0-9:]+$ && "$detected_ipv6" == *:* ]]; then
    printf '%s' "$detected_ipv6" > "$PUBLIC_IPV6_FILE.new" && mv -f "$PUBLIC_IPV6_FILE.new" "$PUBLIC_IPV6_FILE"
  fi
  return 0
}

fetch_public_ip() {
  local url="$1"
  command_exists curl || return 1
  curl -fsS --max-time 4 "$url" 2>/dev/null | tr -d '\r\n[:space:]'
}

ip_meta_json() {
  local public_ip public_ipv4 public_ipv6 detected_ipv4 detected_ipv6 ip_hostname city region country loc org postal timezone asn isp latitude longitude calling_code currency
  if [[ -f "$IP_META_FILE" ]]; then
    public_ip=$(json_value ip < "$IP_META_FILE")
    ip_hostname=$(json_value hostname < "$IP_META_FILE")
    city=$(json_value city < "$IP_META_FILE")
    region=$(json_value region < "$IP_META_FILE")
    country=$(json_value country < "$IP_META_FILE")
    loc=$(json_value loc < "$IP_META_FILE")
    org=$(json_value org < "$IP_META_FILE")
    postal=$(json_value postal < "$IP_META_FILE")
    timezone=$(json_value timezone < "$IP_META_FILE")
  fi
  if [[ -z "${public_ip:-}" && -f "$IP_META_FILE" ]]; then
    public_ip=$(json_value ip < "$IP_META_FILE")
  fi
  public_ipv4=""
  public_ipv6=""
  if [[ "${public_ip:-}" == *:* ]]; then
    public_ipv6="$public_ip"
  else
    public_ipv4="${public_ip:-}"
  fi
  detected_ipv4=$(cat "$PUBLIC_IPV4_FILE" 2>/dev/null || true)
  detected_ipv6=$(cat "$PUBLIC_IPV6_FILE" 2>/dev/null || true)
  if [[ "${detected_ipv4:-}" == *.* && "${detected_ipv4:-}" != *:* ]]; then
    public_ipv4="$detected_ipv4"
  fi
  if [[ "${detected_ipv6:-}" == *:* ]]; then
    public_ipv6="$detected_ipv6"
  fi
  public_ipv4=${PUBLIC_IPV4:-$public_ipv4}
  public_ipv6=${PUBLIC_IPV6:-$public_ipv6}
  public_ip="${public_ipv4:-${public_ipv6:-${public_ip:-}}}"
  if [[ "${org:-}" =~ ^(AS[0-9]+)[[:space:]]+(.+)$ ]]; then
    asn="${BASH_REMATCH[1]}"
    isp="${BASH_REMATCH[2]}"
  else
    asn=""
    isp="${org:-}"
  fi
  latitude=""
  longitude=""
  if [[ "${loc:-}" == *,* ]]; then
    latitude="${loc%%,*}"
    longitude="${loc#*,}"
  fi
  calling_code=""
  currency=""
  printf '"publicIp":"%s","ip":"%s","publicIpv4":"%s","ipv4":"%s","publicIpv6":"%s","ipv6":"%s","ipHostname":"%s","city":"%s","region":"%s","country":"%s","continent":"%s","latitude":"%s","longitude":"%s","postal":"%s","timezone":"%s","callingCode":"%s","currency":"%s","org":"%s","isp":"%s","asn":"%s","company":"%s","route":"%s","networkType":"%s"' \
    "$(json_escape "${public_ip:-}")" "$(json_escape "${public_ip:-}")" \
    "$(json_escape "${public_ipv4:-}")" "$(json_escape "${public_ipv4:-}")" \
    "$(json_escape "${public_ipv6:-}")" "$(json_escape "${public_ipv6:-}")" \
    "$(json_escape "${ip_hostname:-}")" \
    "$(json_escape "${city:-}")" "$(json_escape "${region:-}")" "$(json_escape "${country:-}")" "" \
    "$(json_escape "${latitude:-}")" "$(json_escape "${longitude:-}")" "$(json_escape "${postal:-}")" \
    "$(json_escape "${timezone:-}")" "$(json_escape "$calling_code")" "$(json_escape "$currency")" \
    "$(json_escape "${org:-}")" "$(json_escape "${isp:-}")" "$(json_escape "${asn:-}")" \
    "$(json_escape "${isp:-}")" "" "Data Center"
}

net_json() {
  local now rx tx prev_now prev_rx prev_tx in_bps out_bps elapsed
  now=$(date +%s)
  read -r rx tx < <(net_totals)
  prev_now=0; prev_rx="$rx"; prev_tx="$tx"
  if [[ -f "$STATE_FILE" ]]; then
    read -r prev_now prev_rx prev_tx < "$STATE_FILE" || { prev_now=0; prev_rx="$rx"; prev_tx="$tx"; }
    [[ "$prev_now" =~ ^[0-9]+$ ]] || prev_now=0
    [[ "$prev_rx" =~ ^[0-9]+$ ]] || prev_rx="$rx"
    [[ "$prev_tx" =~ ^[0-9]+$ ]] || prev_tx="$tx"
  fi
  elapsed=$((now - prev_now))
  if (( elapsed > 0 )); then
    in_bps=$(((rx - prev_rx) / elapsed))
    out_bps=$(((tx - prev_tx) / elapsed))
  else
    in_bps=0
    out_bps=0
  fi
  (( in_bps < 0 )) && in_bps=0
  (( out_bps < 0 )) && out_bps=0
  printf '%s %s %s\n' "$now" "$rx" "$tx" > "$STATE_FILE"
  printf '"net":{"inBps":%d,"outBps":%d,"totalIn":%d,"totalOut":%d}' "$in_bps" "$out_bps" "$rx" "$tx"
}

os_json() {
  local platform version arch
  platform="unknown"
  version=""
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    platform="${ID:-unknown}"
    version="${VERSION_ID:-}"
  fi
  arch=$(uname -m)
  printf '"os":{"platform":"%s","version":"%s","arch":"%s","kernel":"%s"}' \
    "$(json_escape "$platform")" "$(json_escape "$version")" "$(json_escape "$arch")" "$(json_escape "$(uname -r)")"
}

cpu_json() {
  local percent model cores load
  percent=$(cpu_percent)
  model=$(awk -F': ' '/model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null || true)
  cores=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0)
  load=$(awk '{ printf "%.2f,%.2f,%.2f", $1, $2, $3 }' /proc/loadavg)
  printf '"cpu":{"percent":%s,"model":"%s","cores":%d,"load":[%s]}' "$percent" "$(json_escape "$model")" "$cores" "$load"
}

build_payload() {
  local hostname uptime
  hostname=$(hostname)
  uptime=$(awk '{ print int($1) }' /proc/uptime)
  printf '{'
  printf '"id":"%s",' "$(json_escape "$SERVER_ID")"
  printf '"probeVersion":"%s",' "$(json_escape "$AGENT_PROBE_VERSION")"
  printf '"name":"%s",' "$(json_escape "$SERVER_NAME")"
  printf '"location":"%s",' "$(json_escape "$SERVER_LOCATION")"
  printf '"hostname":"%s",' "$(json_escape "$hostname")"
  ip_meta_json; printf ','
  printf '"uptimeSeconds":%d,' "$uptime"
  os_json; printf ','
  cpu_json; printf ','
  memory_json; printf ','
  disk_json; printf ','
  net_json; printf ','
  connections_json
  if [[ -s "$CONNECTIVITY_RESULT_FILE" ]]; then
    printf ','
    sed -e 's/^[[:space:]]*{//' -e 's/}[[:space:]]*$//' "$CONNECTIVITY_RESULT_FILE"
  fi
  printf '}'
}

send_once() {
  local payload
  payload=$(build_payload)
  if command_exists curl; then
    curl --fail --silent --show-error --connect-timeout 5 --max-time 10 \
      -H "Authorization: Bearer ${AGENT_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$payload" \
      "${HUB_URL%/}/api/agent/report" >/dev/null
  else
    echo "curl is required" >&2
    return 1
  fi
}

if [[ "${1:-}" == "once" ]]; then
  run_connectivity_checks || true
  send_once
else
  # Keep service probes independent from the fast system-metrics loop, like
  # Nezha's separate RequestTask and ReportSystemState workers.
  connectivity_daemon &
  connectivity_pid=$!
  (while true; do refresh_ip_meta || true; sleep 60; done) &
  metadata_pid=$!
  trap 'kill "$connectivity_pid" "$metadata_pid" 2>/dev/null || true' EXIT
  trap 'exit 0' INT TERM
  failures=0
  last_error_log=0
  while true; do
    if send_once; then
      failures=0
      sleep "$INTERVAL"
    else
      failures=$((failures + 1))
      now=$(date +%s)
      if (( now - last_error_log >= 60 || failures == 1 )); then
        last_error_log=$now
        echo "[$(date -Iseconds)] report failed (${failures}x)" >&2
      fi
      backoff=$(( INTERVAL * (2 ** (failures > 6 ? 6 : failures)) ))
      (( backoff > 60 )) && backoff=60
      sleep "$backoff"
    fi
  done
fi
