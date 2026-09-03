#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo "$0" "$@"
  fi
  exit 1
fi

read -r -p "是否卸载面板并删除全部数据？[Y/N] " answer
[[ "$answer" =~ ^[Yy]$ ]] || exit 0

systemctl disable --now server-probe-monitor.service 2>/dev/null || true
rm -f -- /etc/systemd/system/server-probe-monitor.service
systemctl daemon-reload
systemctl reset-failed server-probe-monitor.service 2>/dev/null || true
rm -rf -- /opt/server-probe-monitor
rm -f -- "$0"
