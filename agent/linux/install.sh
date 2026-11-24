#!/usr/bin/env bash
# VIGIL Agent - instalador para Linux (systemd)
#
#   sudo bash install.sh --server https://SERVIDOR:8443 --token vgl_XXXX [--fingerprint HEX] [--pin sha256//BASE64]
#
#   --fingerprint  SHA-256 do certificado do servidor (quando autoassinado; aparece no painel)
#   --pin          pino da chave publica para o curl baixar o agente com seguranca (autoassinado)
#   --interval     segundos entre envios (padrao 30)
#
# Cria: usuario de sistema "vigil-agent" (sem login), /opt/vigil-agent (codigo + venv),
#       /var/lib/vigil-agent/config.json (0600) e o servico systemd "vigil-agent".
set -euo pipefail

SERVER=""; TOKEN=""; FP=""; PIN=""; INTERVAL=30
INSTALL_DIR=/opt/vigil-agent
DATA_DIR=/var/lib/vigil-agent
SVC=vigil-agent
SVC_USER=vigil-agent
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
step() { printf '\033[36m==> %s\033[0m\n' "$*"; }
ok() { printf '\033[32m    %s\033[0m\n' "$*"; }
die() { printf '\033[31mERRO: %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --fingerprint) FP="$2"; shift 2 ;;
    --pin) PIN="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "opção desconhecida: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "execute como root (sudo)."
[ -n "$SERVER" ] && [ -n "$TOKEN" ] || usage
[[ "$SERVER" == https://* ]] || die "o endereço do servidor deve começar com https://"
[[ "$TOKEN" =~ ^vgl_[A-Za-z0-9_-]{30,64}$ ]] || die "token inválido (deve começar com vgl_)."
command -v systemctl >/dev/null 2>&1 || die "systemd não encontrado neste sistema."

echo
echo "  VIGIL Agent - instalação"
echo "  Servidor: $SERVER"
echo

# ------------------------------------------------------------------ dependencias
pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@"
  elif command -v yum >/dev/null 2>&1; then yum install -y -q "$@"
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install "$@"
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm "$@"
  else die "gerenciador de pacotes não reconhecido; instale python3 e python3-venv manualmente."; fi
}

step "Verificando Python 3"
if ! command -v python3 >/dev/null 2>&1; then pkg_install python3; fi
python3 -c 'import sys; assert sys.version_info >= (3, 8)' || die "é necessário Python 3.8 ou superior."
ok "$(python3 --version)"
if ! python3 -c 'import venv, ensurepip' >/dev/null 2>&1; then
  step "Instalando suporte a venv"
  PYV=$(python3 -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')
  pkg_install "python${PYV}-venv" 2>/dev/null || pkg_install python3-venv || true
fi
command -v curl >/dev/null 2>&1 || pkg_install curl

# ------------------------------------------------------------------ usuario e pastas
step "Criando usuário de serviço '$SVC_USER'"
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
  NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell "$NOLOGIN" "$SVC_USER"
fi
if systemctl is-active --quiet "$SVC" 2>/dev/null; then systemctl stop "$SVC"; fi
install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR"

# ------------------------------------------------------------------ agente
step "Copiando o agente para $INSTALL_DIR"
if [ -f "$HERE/vigil_agent.py" ]; then
  install -m 0644 "$HERE/vigil_agent.py" "$INSTALL_DIR/vigil_agent.py"
else
  CURL_TLS=()
  [ -n "$PIN" ] && CURL_TLS=(-k --pinnedpubkey "$PIN")
  curl -fsSL ${CURL_TLS[@]+"${CURL_TLS[@]}"} "$SERVER/download/linux/vigil_agent.py" -o "$INSTALL_DIR/vigil_agent.py" \
    || die "não foi possível baixar o agente de $SERVER"
  curl -fsSL ${CURL_TLS[@]+"${CURL_TLS[@]}"} "$SERVER/download/linux/uninstall.sh" -o "$INSTALL_DIR/uninstall.sh" || true
fi
[ -f "$HERE/uninstall.sh" ] && install -m 0755 "$HERE/uninstall.sh" "$INSTALL_DIR/uninstall.sh"
[ -f "$INSTALL_DIR/uninstall.sh" ] && chmod 0755 "$INSTALL_DIR/uninstall.sh"

step "Preparando ambiente Python isolado (psutil)"
rm -rf "$INSTALL_DIR/venv"
if python3 -m venv "$INSTALL_DIR/venv" >/dev/null 2>&1 && \
   "$INSTALL_DIR/venv/bin/pip" install --disable-pip-version-check -q --upgrade psutil; then
  PY="$INSTALL_DIR/venv/bin/python"
else
  echo "    pip indisponível; tentando o pacote psutil da distribuição"
  rm -rf "$INSTALL_DIR/venv"
  pkg_install python3-psutil || die "não foi possível instalar o psutil."
  PY=$(command -v python3)
fi
"$PY" -c 'import psutil' || die "psutil não está disponível."
ok "psutil $("$PY" -c 'import psutil; print(psutil.__version__)')"

# ------------------------------------------------------------------ configuracao
step "Gravando configuração (servidor e token)"
CFG="$DATA_DIR/config.json"
ARGS=(--config "$CFG" configure --server "$SERVER" --token "$TOKEN" --interval "$INTERVAL")
[ -n "$FP" ] && ARGS+=(--fingerprint "$FP")
"$PY" "$INSTALL_DIR/vigil_agent.py" "${ARGS[@]}"
chown "$SVC_USER:$SVC_USER" "$CFG"
chmod 0600 "$CFG"

step "Testando autenticação com o servidor"
run_as() {
  if command -v runuser >/dev/null 2>&1; then runuser -u "$SVC_USER" -- "$@"
  else su -s /bin/sh "$SVC_USER" -c "$(printf '%q ' "$@")"; fi
}
run_as "$PY" "$INSTALL_DIR/vigil_agent.py" --config "$CFG" test \
  || die "o agente não conseguiu se autenticar. Confira endereço, token (validade), impressão digital e o firewall do SERVIDOR."

# ------------------------------------------------------------------ systemd
step "Criando o serviço systemd '$SVC'"
cat > "/etc/systemd/system/$SVC.service" <<EOF
[Unit]
Description=VIGIL Agent - monitoramento de infraestrutura
Documentation=file://$INSTALL_DIR
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
ExecStart=$PY $INSTALL_DIR/vigil_agent.py --config $CFG run
Restart=always
RestartSec=10
# endurecimento: o agente so le metricas e grava a propria configuracao
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SVC" >/dev/null
sleep 2
systemctl is-active --quiet "$SVC" || { journalctl -u "$SVC" -n 30 --no-pager; die "o serviço não iniciou."; }
ok "Serviço ativo e habilitado na inicialização."

echo
printf '\033[32m  VIGIL Agent instalado com sucesso!\033[0m\n'
echo "  O computador já deve aparecer como Online no painel do VIGIL."
echo "  Status:      systemctl status $SVC"
echo "  Log:         journalctl -u $SVC -f   (e $DATA_DIR/agent.log)"
echo "  Desinstalar: sudo bash $INSTALL_DIR/uninstall.sh"
echo
