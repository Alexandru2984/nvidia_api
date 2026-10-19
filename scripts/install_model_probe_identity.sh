#!/usr/bin/env bash
# Provision the credential-minimal model-probe identity and Ed25519 keypair.
# The backend deployment owns the service unit; this installer never executes
# uncommitted application code or starts the probe.
set -Eeuo pipefail
umask 077

REPO_DIR='/home/micu/nvidia'
SOURCE_ENV="$REPO_DIR/backend/.env"
SOURCE_SYSUSERS="$REPO_DIR/ops/sysusers.d/aichat-model-probe.conf"
TARGET_SYSUSERS='/etc/sysusers.d/aichat-model-probe.conf'
CONFIG_DIR='/etc/aichat'
API_CREDENTIAL="$CONFIG_DIR/model-probe-api-key"
PRIVATE_KEY="$CONFIG_DIR/model-status-private.pem"
PUBLIC_KEY="$CONFIG_DIR/model-status-public.pem"
PROBE_USER='aichat-model-probe'
rotate_signing_key=0
temporary=''
config_dir_created=0
completed=0

if [[ "${1:-}" == '--rotate-signing-key' ]]; then
  rotate_signing_key=1
  shift
fi
if (( $# != 0 )); then
  echo 'Usage: sudo scripts/install_model_probe_identity.sh [--rotate-signing-key]' >&2
  exit 2
fi

if (( EUID != 0 )); then
  echo 'ERROR: model-probe identity installation must run as root' >&2
  exit 1
fi
for command in git install systemd-sysusers getent id openssl cmp stat; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
for source in "$SOURCE_ENV" "$SOURCE_SYSUSERS"; do
  [[ -f "$source" && ! -L "$source" ]] || {
    echo "ERROR: unsafe model-probe source: $source" >&2
    exit 1
  }
done
if ! git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" diff --quiet -- \
   || ! git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" diff --cached --quiet --; then
  echo 'ERROR: tracked repository changes must be committed before installation' >&2
  exit 1
fi
env_mode="$(stat -c '%a' -- "$SOURCE_ENV")"
(( (8#$env_mode & 037) == 0 )) || {
  echo 'ERROR: application dotenv permissions are too broad' >&2
  exit 1
}

temporary="$(mktemp -d /run/aichat-model-probe-install.XXXXXX)"

backup_target() {
  local name="$1" target="$2"
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" ]] || {
      echo "ERROR: unsafe installed model-probe target: $target" >&2
      return 1
    }
    cp -a -- "$target" "$temporary/$name"
  else
    : > "$temporary/$name.missing"
  fi
}

restore_target() {
  local name="$1" target="$2"
  if [[ -f "$temporary/$name" ]]; then
    cp -a -- "$temporary/$name" "$target"
  elif [[ -f "$temporary/$name.missing" ]]; then
    unlink -- "$target" 2>/dev/null || true
  fi
}

handle_exit() {
  local status="$?"
  trap - EXIT INT TERM
  if (( ! completed )); then
    restore_target sysusers "$TARGET_SYSUSERS"
    restore_target api "$API_CREDENTIAL"
    restore_target private "$PRIVATE_KEY"
    restore_target public "$PUBLIC_KEY"
    if (( config_dir_created )); then
      rmdir -- "$CONFIG_DIR" 2>/dev/null || true
    fi
  fi
  [[ -z "$temporary" || ! -d "$temporary" ]] \
    || rm -rf --one-file-system -- "$temporary"
  exit "$status"
}
trap handle_exit EXIT INT TERM

backup_target sysusers "$TARGET_SYSUSERS"
if [[ -e "$CONFIG_DIR" || -L "$CONFIG_DIR" ]]; then
  [[ -d "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || {
    echo 'ERROR: /etc/aichat is not a safe directory' >&2
    exit 1
  }
else
  install -d -o root -g aichat -m 0750 -- "$CONFIG_DIR"
  config_dir_created=1
fi
for spec in \
  "api:$API_CREDENTIAL" \
  "private:$PRIVATE_KEY" \
  "public:$PUBLIC_KEY"; do
  backup_target "${spec%%:*}" "${spec#*:}"
done

# Extract only the provider key. The probe never receives database, SMTP,
# Django, 2FA, audit, or other application credentials from the dotenv.
/opt/aichat-python-current/bin/python - "$SOURCE_ENV" "$temporary/api-key" <<'PY'
import os
import sys
from dotenv import dotenv_values

source, target = sys.argv[1:]
value = dotenv_values(source).get('NVIDIA_API_KEY')
if not isinstance(value, str) or not 16 <= len(value) <= 4096:
    raise SystemExit('ERROR: NVIDIA_API_KEY is missing or outside the safe size bound')
if value != value.strip() or any(ord(char) < 33 or ord(char) == 127 for char in value):
    raise SystemExit('ERROR: NVIDIA_API_KEY contains invalid whitespace or control bytes')
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
    output.write(value + '\n')
    output.flush()
    os.fsync(output.fileno())
PY

if (( ! rotate_signing_key )) \
   && [[ -e "$PRIVATE_KEY" || -L "$PRIVATE_KEY" \
        || -e "$PUBLIC_KEY" || -L "$PUBLIC_KEY" ]]; then
  [[ -f "$PRIVATE_KEY" && ! -L "$PRIVATE_KEY" \
     && -f "$PUBLIC_KEY" && ! -L "$PUBLIC_KEY" ]] || {
    echo 'ERROR: model-status keypair is incomplete or unsafe' >&2
    exit 1
  }
  openssl pkey -in "$PRIVATE_KEY" -pubout -out "$temporary/derived-public.pem" \
    >/dev/null 2>&1
  cmp --silent -- "$temporary/derived-public.pem" "$PUBLIC_KEY" || {
    echo 'ERROR: installed model-status public/private keys do not match' >&2
    exit 1
  }
  cp -- "$PRIVATE_KEY" "$temporary/new-private.pem"
  cp -- "$PUBLIC_KEY" "$temporary/new-public.pem"
else
  openssl genpkey -algorithm ED25519 -out "$temporary/new-private.pem" \
    >/dev/null 2>&1
  openssl pkey -in "$temporary/new-private.pem" -pubout \
    -out "$temporary/new-public.pem" >/dev/null 2>&1
fi

install -o root -g root -m 0600 -- "$temporary/api-key" "$API_CREDENTIAL"
install -o root -g root -m 0600 -- "$temporary/new-private.pem" "$PRIVATE_KEY"
install -o root -g aichat -m 0640 -- "$temporary/new-public.pem" "$PUBLIC_KEY"
install -o root -g root -m 0644 -- "$SOURCE_SYSUSERS" "$TARGET_SYSUSERS"
systemd-sysusers "$TARGET_SYSUSERS"

probe_group="$(id -gn "$PROBE_USER")"
probe_home="$(getent passwd "$PROBE_USER" | cut -d: -f6)"
probe_shell="$(getent passwd "$PROBE_USER" | cut -d: -f7)"
[[ "$probe_group" == "$PROBE_USER" \
   && "$probe_home" == '/var/lib/aichat-model-probe' \
   && "$probe_shell" == '/usr/sbin/nologin' ]] || {
  echo 'ERROR: model-probe identity does not match the restricted service shape' >&2
  exit 1
}
[[ "$(stat -c '%a:%U:%G' "$CONFIG_DIR")" == '750:root:aichat' \
   && "$(stat -c '%a:%U:%G' "$API_CREDENTIAL")" == '600:root:root' \
   && "$(stat -c '%a:%U:%G' "$PRIVATE_KEY")" == '600:root:root' \
   && "$(stat -c '%a:%U:%G' "$PUBLIC_KEY")" == '640:root:aichat' ]] || {
  echo 'ERROR: installed model-probe permissions are unsafe' >&2
  exit 1
}

completed=1
echo 'Isolated model-probe identity and signing credentials installed.'
