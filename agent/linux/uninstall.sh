#!/usr/bin/env bash
# VIGIL Agent - desinstalador para Linux
#   sudo bash /opt/vigil-agent/uninstall.sh [--keep-config]
set -euo pipefail
KEEP=0
[ "${1:-}" = "--keep-config" ] && KEEP=1
[ "$(id -u)" -eq 0 ] || { echo "Execute como root (sudo)."; exit 1; }

SVC=vigil-agent
if systemctl list-unit-files "$SVC.service" >/dev/null 2>&1; then
  systemctl disable --now "$SVC" 2>/dev/null || true
fi
rm -f "/etc/systemd/system/$SVC.service"
systemctl daemon-reload
rm -rf /opt/vigil-agent
if [ "$KEEP" -eq 0 ]; then
  rm -rf /var/lib/vigil-agent
  id -u vigil-agent >/dev/null 2>&1 && userdel vigil-agent 2>/dev/null || true
fi
echo "VIGIL Agent desinstalado."
echo "Lembre-se de revogar ou excluir este dispositivo no painel do VIGIL."
