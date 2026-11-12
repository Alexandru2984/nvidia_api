#!/usr/bin/env bash
# Atomically move AI Chat Hub application secrets from the runtime dotenv into
# root-managed files, retaining the old dotenv only in /run during validation.
set -euo pipefail
umask 077

REPO_DIR='/home/micu/nvidia'
RUNTIME_DIR='/home/micu/nvidia/backend'
ENV_FILE="$RUNTIME_DIR/.env"
CREDENTIAL_PARENT='/etc/aichat'
CREDENTIAL_DIR="$CREDENTIAL_PARENT/application-credentials"
CHECKER="$REPO_DIR/scripts/check_application_credentials.py"
PYTHON='/opt/aichat-python-current/bin/python'
BACKUP_SCRIPT="$REPO_DIR/scripts/backup_db.sh"
RESTORE_SCRIPT="$REPO_DIR/scripts/backup_restore_drill.sh"
SERVICE='aichat-backend.service'
WATCHER='aichat-config-watch.path'
credential_files=(
  django-secret-key
  two-factor-keys
  admin-audit-keys
  db-password
  nvidia-api-key
  smtp-password
)

temporary=''
credential_stage=''
runtime_next=''
environment_switched=0
credentials_switched=0
completed=0
watcher_was_active=0

remove_credential_directory() {
  local directory="$1" filename
  [[ -n "$directory" && "$directory" == "$CREDENTIAL_PARENT"/* \
    && -d "$directory" && ! -L "$directory" ]] || return 0
  for filename in "${credential_files[@]}"; do
    unlink -- "$directory/$filename" 2>/dev/null || true
  done
  rmdir -- "$directory" 2>/dev/null || true
}

restore_watcher() {
  if (( watcher_was_active )); then
    systemctl start "$WATCHER"
  fi
}

cleanup_temporary() {
  [[ -n "$runtime_next" ]] && unlink -- "$runtime_next" 2>/dev/null || true
  remove_credential_directory "$credential_stage"
  if [[ -n "$temporary" && -d "$temporary" && ! -L "$temporary" ]]; then
    unlink -- "$temporary/env.before" 2>/dev/null || true
    unlink -- "$temporary/env.after" 2>/dev/null || true
    unlink -- "$temporary/credential-parent.acl" 2>/dev/null || true
    rmdir -- "$temporary" 2>/dev/null || true
  fi
}

rollback() {
  local status="${1:-1}" restore_next
  trap - ERR INT TERM EXIT
  if (( completed )); then
    return
  fi
  echo 'ERROR: application credential migration failed; restoring prior runtime configuration' >&2
  if (( environment_switched )) && [[ -f "$temporary/env.before" ]]; then
    restore_next="$RUNTIME_DIR/.runtime-config-rollback-$$"
    install -o micu -g aichat -m 0640 -- "$temporary/env.before" "$restore_next"
    mv -Tf -- "$restore_next" "$ENV_FILE"
  fi
  if (( credentials_switched )); then
    remove_credential_directory "$CREDENTIAL_DIR"
  fi
  if [[ -f "$temporary/credential-parent.acl" ]]; then
    setfacl --restore="$temporary/credential-parent.acl" >/dev/null 2>&1 || true
  fi
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  restore_watcher >/dev/null 2>&1 || true
  cleanup_temporary
  exit "$status"
}

if (( EUID != 0 )); then
  echo 'ERROR: application credential migration must run as root' >&2
  exit 1
fi
for command in git install mktemp mv stat setfacl getfacl runuser systemctl curl flock; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
[[ -x "$PYTHON" && -x "$CHECKER" && -x "$BACKUP_SCRIPT" && -x "$RESTORE_SCRIPT" ]] || {
  echo 'ERROR: required credential migration tooling is missing or unsafe' >&2
  exit 1
}
if [[ -n "$(git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" status --porcelain)" ]]; then
  echo 'ERROR: repository changes must be committed before credential migration' >&2
  exit 1
fi
exec 9>'/run/aichat-credential-migration.lock'
flock -n 9 || { echo 'ERROR: another credential migration is running' >&2; exit 1; }

if [[ -d "$CREDENTIAL_DIR" && ! -L "$CREDENTIAL_DIR" ]]; then
  "$PYTHON" "$CHECKER" --env-file "$ENV_FILE" --credential-dir "$CREDENTIAL_DIR"
  echo 'Application credentials were already migrated.'
  exit 0
fi
[[ ! -e "$CREDENTIAL_DIR" && ! -L "$CREDENTIAL_DIR" ]] || {
  echo 'ERROR: credential destination already exists with an unsafe type' >&2
  exit 1
}
[[ -d "$CREDENTIAL_PARENT" && ! -L "$CREDENTIAL_PARENT" \
  && "$(stat -c '%U:%G:%a' -- "$CREDENTIAL_PARENT")" == 'root:aichat:750' ]] || {
  echo 'ERROR: credential parent metadata is unsafe' >&2
  exit 1
}

temporary="$(mktemp -d /run/aichat-credential-migration.XXXXXX)"
credential_stage="$(mktemp -d "$CREDENTIAL_PARENT/.application-credentials.XXXXXX")"
runtime_next="$RUNTIME_DIR/.runtime-config-migration-$$"
cp -a -- "$ENV_FILE" "$temporary/env.before"
getfacl --absolute-names -- "$CREDENTIAL_PARENT" > "$temporary/credential-parent.acl"
trap 'rollback "$?"' ERR INT TERM EXIT

if systemctl is-active --quiet "$WATCHER"; then
  watcher_was_active=1
  systemctl stop "$WATCHER"
fi

"$PYTHON" "$CHECKER" \
  --env-file "$ENV_FILE" \
  --credential-dir "$CREDENTIAL_DIR" \
  --stage-output-env "$temporary/env.after" \
  --stage-credential-dir "$credential_stage"

chown root:aichat -- "$credential_stage" "$credential_stage"/*
chmod 0750 -- "$credential_stage"
chmod 0640 -- "$credential_stage"/*
setfacl -b -- "$credential_stage" "$credential_stage"/*
setfacl -m 'u:micu:--x' -- "$CREDENTIAL_PARENT"
setfacl -m 'u:micu:r-x' -- "$credential_stage"
setfacl -m 'u:micu:r--' -- "$credential_stage"/*

mv -T -- "$credential_stage" "$CREDENTIAL_DIR"
credential_stage=''
credentials_switched=1
install -o micu -g aichat -m 0640 -- "$temporary/env.after" "$runtime_next"
mv -Tf -- "$runtime_next" "$ENV_FILE"
runtime_next=''
environment_switched=1

"$PYTHON" "$CHECKER" --env-file "$ENV_FILE" --credential-dir "$CREDENTIAL_DIR"
for credential in "$CREDENTIAL_DIR"/*; do
  runuser --user aichat -- test -r "$credential"
  runuser --user aichat -- test ! -w "$credential"
  runuser --user micu -- test -r "$credential"
  runuser --user micu -- test ! -w "$credential"
done

runuser --user aichat -- env --chdir=/opt/aichat-backend-current \
  AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1 \
  "$PYTHON" manage.py check --deploy
systemctl restart "$SERVICE"
for _attempt in {1..45}; do
  if systemctl is-active --quiet "$SERVICE" \
    && curl --silent --show-error --fail --max-time 5 --output /dev/null \
      --resolve 'aichat.micutu.com:443:127.0.0.1' \
      'https://aichat.micutu.com/api/health/'; then
    break
  fi
  sleep 1
done
systemctl is-active --quiet "$SERVICE"
curl --silent --show-error --fail --max-time 5 --output /dev/null \
  --resolve 'aichat.micutu.com:443:127.0.0.1' \
  'https://aichat.micutu.com/api/health/'

runuser --user micu -- env HOME=/home/micu \
  AICHAT_RUNTIME_DIR="$RUNTIME_DIR" AICHAT_PYTHON="$PYTHON" \
  "$BACKUP_SCRIPT"
runuser --user micu -- env HOME=/home/micu \
  AICHAT_RUNTIME_DIR="$RUNTIME_DIR" \
  AICHAT_APP_DIR=/opt/aichat-backend-current AICHAT_PYTHON="$PYTHON" \
  "$RESTORE_SCRIPT"

restore_watcher
if (( watcher_was_active )); then
  systemctl is-active --quiet "$WATCHER"
fi
cleanup_temporary
completed=1
trap - ERR INT TERM EXIT
printf 'Application credential migration completed with no persistent plaintext rollback copy.\n'
