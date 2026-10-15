#!/usr/bin/env bash
set -Eeuo pipefail

if (( EUID != 0 )); then
  echo 'ERROR: run this installer as root' >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
SERVICE_SOURCE="$REPO_DIR/backend/chat/document_parser_service.py"
WORKER_SOURCE="$REPO_DIR/backend/chat/document_worker.py"
UNIT_SOURCE="$REPO_DIR/ops/systemd/aichat-document-parser.service"
SERVICE_TARGET='/usr/local/libexec/aichat-document-parser'
WORKER_TARGET='/usr/local/libexec/aichat-document-worker'
UNIT_TARGET='/etc/systemd/system/aichat-document-parser.service'

for source in "$SERVICE_SOURCE" "$WORKER_SOURCE" "$UNIT_SOURCE"; do
  if [[ ! -f "$source" || -L "$source" ]]; then
    echo "ERROR: parser source is missing or unsafe: $source" >&2
    exit 1
  fi
done
if [[ ! -x /opt/aichat-python-current/bin/python ]]; then
  echo 'ERROR: immutable production Python environment is unavailable' >&2
  exit 1
fi
if ! id aichat >/dev/null 2>&1; then
  echo 'ERROR: the aichat service identity does not exist' >&2
  exit 1
fi

if ! getent group aichat-parser >/dev/null; then
  groupadd --system aichat-parser
fi
if ! id aichat-parser >/dev/null 2>&1; then
  useradd --system --gid aichat-parser --home-dir /nonexistent --no-create-home \
    --shell /usr/sbin/nologin aichat-parser
fi

parser_group="$(id -gn aichat-parser)"
parser_home="$(getent passwd aichat-parser | cut -d: -f6)"
parser_shell="$(getent passwd aichat-parser | cut -d: -f7)"
if [[ "$parser_group" != 'aichat-parser' || "$parser_home" != '/nonexistent' \
  || "$parser_shell" != '/usr/sbin/nologin' ]]; then
  echo 'ERROR: existing aichat-parser identity does not match the restricted service shape' >&2
  exit 1
fi

install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 -- "$SERVICE_SOURCE" "$SERVICE_TARGET"
install -o root -g root -m 0755 -- "$WORKER_SOURCE" "$WORKER_TARGET"
install -o root -g root -m 0644 -- "$UNIT_SOURCE" "$UNIT_TARGET"
usermod -a -G aichat-parser aichat

systemctl daemon-reload
systemctl enable aichat-document-parser.service
systemctl reset-failed aichat-document-parser.service
systemctl restart aichat-document-parser.service

parser_ready=0
for _ in $(seq 1 30); do
  if runuser --user aichat -- python3 -c \
    "import socket,struct; h=struct.Struct('!4sBII'); r=struct.Struct('!4sBI'); c=socket.socket(socket.AF_UNIX); c.settimeout(1); c.connect('/run/aichat-document-parser/parser.sock'); c.sendall(h.pack(b'AIP1',0,0,0)); data=c.recv(r.size); raise SystemExit(0 if data == r.pack(b'AIP1',0,0) and not c.recv(1) else 1)" \
    >/dev/null 2>&1; then
    parser_ready=1
    break
  fi
  sleep 1
done
if (( ! parser_ready )); then
  systemctl status aichat-document-parser.service --no-pager >&2 || true
  echo 'ERROR: isolated document parser did not become ready' >&2
  exit 1
fi

systemctl is-active --quiet aichat-document-parser.service
socket_mode="$(stat -c '%a' /run/aichat-document-parser/parser.sock)"
socket_group="$(stat -c '%G' /run/aichat-document-parser/parser.sock)"
if [[ "$socket_mode" != '660' || "$socket_group" != 'aichat-parser' ]]; then
  echo 'ERROR: parser socket ownership or mode is unsafe' >&2
  exit 1
fi

echo 'Isolated document parser installed and active.'
