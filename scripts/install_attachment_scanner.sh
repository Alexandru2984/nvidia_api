#!/usr/bin/env bash
set -Eeuo pipefail

if (( EUID != 0 )); then
  echo 'ERROR: run this installer as root' >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
CLAMD_CONFIG="$REPO_DIR/ops/clamav/clamd.conf"
CLAMD_UNIT="$REPO_DIR/ops/systemd/aichat-clamd.service"
FRESHCLAM_DROPIN="$REPO_DIR/ops/systemd/clamav-freshclam.service.d/aichat-hardening.conf"

for package in clamav-daemon clamav-freshclam; do
  if ! dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -qx 'ii '; then
    echo "ERROR: install $package from the Ubuntu repository first" >&2
    exit 1
  fi
done
if ! id aichat >/dev/null 2>&1; then
  echo 'ERROR: the aichat service identity does not exist' >&2
  exit 1
fi

install -o root -g root -m 0644 -- "$CLAMD_CONFIG" /etc/clamav/clamd.conf
install -d -o root -g root -m 0755 /etc/systemd/system/clamav-freshclam.service.d
install -o root -g root -m 0644 -- "$CLAMD_UNIT" \
  /etc/systemd/system/aichat-clamd.service
install -o root -g root -m 0644 -- "$FRESHCLAM_DROPIN" \
  /etc/systemd/system/clamav-freshclam.service.d/aichat-hardening.conf
usermod -a -G clamav aichat

systemctl daemon-reload
systemctl enable clamav-freshclam.service
systemctl restart clamav-freshclam.service

for _ in $(seq 1 180); do
  if [[ -f /var/lib/clamav/main.cvd || -f /var/lib/clamav/main.cld ]] \
    && [[ -f /var/lib/clamav/daily.cvd || -f /var/lib/clamav/daily.cld ]]; then
    break
  fi
  sleep 1
done
if ! { [[ -f /var/lib/clamav/main.cvd || -f /var/lib/clamav/main.cld ]] \
  && [[ -f /var/lib/clamav/daily.cvd || -f /var/lib/clamav/daily.cld ]]; }; then
  echo 'ERROR: ClamAV signature download did not complete' >&2
  exit 1
fi

systemctl disable --now clamav-daemon.service clamav-daemon.socket
systemctl enable aichat-clamd.service
systemctl reset-failed aichat-clamd.service
systemctl restart aichat-clamd.service

scanner_ready=0
for _ in $(seq 1 90); do
  if runuser --user aichat -- python3 -c \
    "import socket; client=socket.socket(socket.AF_UNIX); client.settimeout(1); client.connect('/run/clamav/clamd.ctl'); client.sendall(b'zPING\\0'); raise SystemExit(0 if client.recv(16) == b'PONG\\0' else 1)" \
    >/dev/null 2>&1; then
    scanner_ready=1
    break
  fi
  sleep 1
done
if (( ! scanner_ready )); then
  systemctl status aichat-clamd.service --no-pager >&2 || true
  echo 'ERROR: ClamAV did not become ready' >&2
  exit 1
fi

systemctl is-active --quiet aichat-clamd.service
systemctl is-active --quiet clamav-freshclam.service

socket_mode="$(stat -c '%a' /run/clamav/clamd.ctl)"
socket_group="$(stat -c '%G' /run/clamav/clamd.ctl)"
if [[ "$socket_mode" != '660' || "$socket_group" != 'clamav' ]]; then
  echo 'ERROR: ClamAV socket ownership or mode is unsafe' >&2
  exit 1
fi

echo 'Local attachment malware scanner installed and active.'
