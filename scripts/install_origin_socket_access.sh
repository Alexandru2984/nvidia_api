#!/usr/bin/env bash
# Provision the one-purpose group shared only by AI Chat Hub and nginx workers.
set -euo pipefail
umask 022

ORIGIN_GROUP='aichat-origin'
BACKEND_USER='aichat'
PROXY_USER='www-data'

if (( EUID != 0 )); then
  echo 'ERROR: origin-socket access installation must run as root' >&2
  exit 1
fi
for command in getent groupadd id usermod; do
  command -v "$command" >/dev/null || {
    echo "ERROR: missing required command: $command" >&2
    exit 1
  }
done
getent passwd "$BACKEND_USER" >/dev/null || {
  echo "ERROR: backend identity is missing: $BACKEND_USER" >&2
  exit 1
}
getent passwd "$PROXY_USER" >/dev/null || {
  echo "ERROR: nginx identity is missing: $PROXY_USER" >&2
  exit 1
}
if ! getent group "$ORIGIN_GROUP" >/dev/null; then
  groupadd --system "$ORIGIN_GROUP"
fi
if ! id -nG "$PROXY_USER" | tr ' ' '\n' | grep -Fxq "$ORIGIN_GROUP"; then
  usermod --append --groups "$ORIGIN_GROUP" "$PROXY_USER"
fi
id -nG "$PROXY_USER" | tr ' ' '\n' | grep -Fxq "$ORIGIN_GROUP" || {
  echo 'ERROR: nginx identity did not receive origin-socket access' >&2
  exit 1
}
if id -nG micu | tr ' ' '\n' | grep -Fxq "$ORIGIN_GROUP"; then
  echo 'ERROR: interactive identity must not be a member of the origin group' >&2
  exit 1
fi
echo 'AI Chat Hub origin-socket group is provisioned; service reloads are still required.'
