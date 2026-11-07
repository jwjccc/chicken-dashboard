#!/usr/bin/env bash
set -euo pipefail
# Use the same panel-generated lifecycle manager as the admin install command.
# Its persisted panel identity and legacy ownership fingerprints are authoritative.
HUB_URL="${PROBE_HUB_URL:-${HUB_URL:?HUB_URL is required}}"
export PROBE_HUB_URL="$HUB_URL"
export PROBE_AGENT_TOKEN="${PROBE_AGENT_TOKEN:-${AGENT_TOKEN:?AGENT_TOKEN is required}}"
export PROBE_SERVER_ID="${PROBE_SERVER_ID:-${SERVER_ID:-$(hostname)}}"
export PROBE_SERVER_NAME="${PROBE_SERVER_NAME:-${SERVER_NAME:-$(hostname)}}"
export PROBE_SERVER_LOCATION="${PROBE_SERVER_LOCATION:-${SERVER_LOCATION:-}}"
export PROBE_INTERVAL="${PROBE_INTERVAL:-${INTERVAL:-2}}"
export PROBE_CONNECTIVITY_INTERVAL="${PROBE_CONNECTIVITY_INTERVAL:-${CONNECTIVITY_INTERVAL:-60}}"
export PROBE_REUSE_EXISTING="${PROBE_REUSE_EXISTING:-1}"
umask 077
script=$(mktemp)
trap 'rm -f -- "$script"' EXIT
curl --fail --location --silent --show-error --connect-timeout 10 --max-time 60 "${HUB_URL%/}/api/agent/install.sh" -o "$script"
bash -n "$script"
bash "$script"
