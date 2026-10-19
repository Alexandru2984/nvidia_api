#!/usr/bin/env bash
# Install the AI Chat Hub monitor under a dedicated identity with least-privilege
# backup metadata ACLs and a systemd-delivered Telegram credential.
set -euo pipefail
umask 077

REPO_DIR='/home/micu/nvidia'
SOURCE_MONITOR="$REPO_DIR/scripts/security_monitor.py"
SOURCE_SERVICE="$REPO_DIR/ops/systemd/aichat-security-monitor.service"
SOURCE_TIMER="$REPO_DIR/ops/systemd/aichat-security-monitor.timer"
SOURCE_SYSUSERS="$REPO_DIR/ops/sysusers.d/aichat-monitor.conf"
SOURCE_CONFIG_SERVICE="$REPO_DIR/ops/systemd/aichat-config-watch.service"
SOURCE_CONFIG_PATH="$REPO_DIR/ops/systemd/aichat-config-watch.path"
SOURCE_RESTORE_DRILL="$REPO_DIR/scripts/backup_restore_drill.sh"
SOURCE_RESTORE_SERVICE="$REPO_DIR/ops/systemd/aichat-restore-drill.service"
SOURCE_RESTORE_TIMER="$REPO_DIR/ops/systemd/aichat-restore-drill.timer"
TARGET_MONITOR='/usr/local/libexec/aichat-security-monitor'
TARGET_SERVICE='/etc/systemd/system/aichat-security-monitor.service'
TARGET_TIMER='/etc/systemd/system/aichat-security-monitor.timer'
TARGET_SYSUSERS='/etc/sysusers.d/aichat-monitor.conf'
TARGET_CONFIG_SERVICE='/etc/systemd/system/aichat-config-watch.service'
TARGET_CONFIG_PATH='/etc/systemd/system/aichat-config-watch.path'
TARGET_RESTORE_DRILL='/usr/local/libexec/aichat-restore-drill'
TARGET_RESTORE_SERVICE='/etc/systemd/system/aichat-restore-drill.service'
TARGET_RESTORE_TIMER='/etc/systemd/system/aichat-restore-drill.timer'
CREDENTIALS='/home/micu/scripts/.env'
BACKUP_PARENT='/home/micu/backups'
BACKUP_DIR='/home/micu/backups/nvidia_db'
RESTORE_LOG="$BACKUP_DIR/restore-drill.log"
STATE_DIR='/var/lib/aichat-security-monitor'
STATE_FILE="$STATE_DIR/state.json"
MONITOR_USER='aichat-monitor'
temporary=''
completed=0

if (( EUID != 0 )); then
  echo 'ERROR: security-monitor installation must run as root' >&2
  exit 1
fi
for command in getfacl setfacl systemctl systemd-sysusers install runuser git getent python3 cmp; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
if ! git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" diff --quiet -- \
   || ! git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" diff --cached --quiet --; then
  echo 'ERROR: tracked repository changes must be committed before installation' >&2
  exit 1
fi
for source in \
  "$SOURCE_MONITOR" "$SOURCE_SERVICE" "$SOURCE_TIMER" "$SOURCE_SYSUSERS" \
  "$SOURCE_CONFIG_SERVICE" "$SOURCE_CONFIG_PATH" "$SOURCE_RESTORE_DRILL" \
  "$SOURCE_RESTORE_SERVICE" "$SOURCE_RESTORE_TIMER"; do
  [[ -f "$source" && ! -L "$source" ]] || {
    echo "ERROR: unsafe installation source: $source" >&2
    exit 1
  }
done
for path in "$CREDENTIALS" "$RESTORE_LOG"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    echo "ERROR: required private file is missing or unsafe: $path" >&2
    exit 1
  }
done
credential_mode="$(stat -c '%a' -- "$CREDENTIALS")"
(( (8#$credential_mode & 077) == 0 )) || {
  echo 'ERROR: Telegram credential permissions are too broad' >&2
  exit 1
}
[[ -d "$BACKUP_PARENT" && ! -L "$BACKUP_PARENT" \
   && -d "$BACKUP_DIR" && ! -L "$BACKUP_DIR" \
   && -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || {
  echo 'ERROR: monitor state or backup directories are missing or unsafe' >&2
  exit 1
}
if [[ -e "$STATE_FILE" || -L "$STATE_FILE" ]]; then
  [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || {
    echo 'ERROR: monitor state is not a regular file' >&2
    exit 1
  }
fi

temporary="$(mktemp -d /run/aichat-monitor-install.XXXXXX)"
getfacl --absolute-names -- "$BACKUP_PARENT" "$BACKUP_DIR" "$RESTORE_LOG" \
  > "$temporary/backup.acl"
for target_name in \
  monitor service timer sysusers config_service config_path \
  restore_drill restore_service restore_timer; do
  case "$target_name" in
    monitor) target="$TARGET_MONITOR" ;;
    service) target="$TARGET_SERVICE" ;;
    timer) target="$TARGET_TIMER" ;;
    sysusers) target="$TARGET_SYSUSERS" ;;
    config_service) target="$TARGET_CONFIG_SERVICE" ;;
    config_path) target="$TARGET_CONFIG_PATH" ;;
    restore_drill) target="$TARGET_RESTORE_DRILL" ;;
    restore_service) target="$TARGET_RESTORE_SERVICE" ;;
    restore_timer) target="$TARGET_RESTORE_TIMER" ;;
  esac
  if [[ -e "$target" || -L "$target" ]]; then
    [[ -f "$target" && ! -L "$target" ]] || {
      echo "ERROR: unsafe installed target: $target" >&2
      exit 1
    }
    cp -a -- "$target" "$temporary/$target_name"
  else
    : > "$temporary/$target_name.missing"
  fi
done
state_dir_owner="$(stat -c '%u:%g:%a' -- "$STATE_DIR")"
if [[ -f "$STATE_FILE" ]]; then
  state_file_owner="$(stat -c '%u:%g:%a' -- "$STATE_FILE")"
  cp -a -- "$STATE_FILE" "$temporary/state"
else
  state_file_owner='missing'
fi
timer_enabled="$(systemctl is-enabled aichat-security-monitor.timer 2>/dev/null || true)"
timer_active="$(systemctl is-active aichat-security-monitor.timer 2>/dev/null || true)"
config_path_enabled="$(systemctl is-enabled aichat-config-watch.path 2>/dev/null || true)"
config_path_active="$(systemctl is-active aichat-config-watch.path 2>/dev/null || true)"
restore_timer_enabled="$(systemctl is-enabled aichat-restore-drill.timer 2>/dev/null || true)"
restore_timer_active="$(systemctl is-active aichat-restore-drill.timer 2>/dev/null || true)"

restore_target() {
  local name="$1" target="$2"
  if [[ -f "$temporary/$name" ]]; then
    cp -a -- "$temporary/$name" "$target"
  elif [[ -f "$temporary/$name.missing" ]]; then
    unlink -- "$target" 2>/dev/null || true
  fi
}

rollback() {
  local status="${1:-1}" uid gid mode
  trap - ERR INT TERM
  if (( completed )); then
    return
  fi
  systemctl stop aichat-security-monitor.timer aichat-security-monitor.service \
    aichat-config-watch.path aichat-config-watch.service \
    aichat-restore-drill.timer aichat-restore-drill.service \
    >/dev/null 2>&1 || true
  restore_target monitor "$TARGET_MONITOR"
  restore_target service "$TARGET_SERVICE"
  restore_target timer "$TARGET_TIMER"
  restore_target sysusers "$TARGET_SYSUSERS"
  restore_target config_service "$TARGET_CONFIG_SERVICE"
  restore_target config_path "$TARGET_CONFIG_PATH"
  restore_target restore_drill "$TARGET_RESTORE_DRILL"
  restore_target restore_service "$TARGET_RESTORE_SERVICE"
  restore_target restore_timer "$TARGET_RESTORE_TIMER"
  setfacl --restore="$temporary/backup.acl" >/dev/null 2>&1 || true
  IFS=: read -r uid gid mode <<< "$state_dir_owner"
  chown "$uid:$gid" -- "$STATE_DIR" 2>/dev/null || true
  chmod "$mode" -- "$STATE_DIR" 2>/dev/null || true
  if [[ "$state_file_owner" != missing && -f "$STATE_FILE" ]]; then
    cp -a -- "$temporary/state" "$STATE_FILE"
    IFS=: read -r uid gid mode <<< "$state_file_owner"
    chown "$uid:$gid" -- "$STATE_FILE" 2>/dev/null || true
    chmod "$mode" -- "$STATE_FILE" 2>/dev/null || true
  elif [[ "$state_file_owner" == missing ]]; then
    unlink -- "$STATE_FILE" 2>/dev/null || true
  fi
  systemctl daemon-reload >/dev/null 2>&1 || true
  # Preserve the journal evidence while removing the failed runtime state from
  # the attempted unit. Otherwise a first-install rollback leaves a failed,
  # not-found ghost in `systemctl --failed` after all files were restored.
  systemctl reset-failed aichat-restore-drill.service >/dev/null 2>&1 || true
  if [[ "$timer_enabled" == enabled ]]; then
    systemctl enable aichat-security-monitor.timer >/dev/null 2>&1 || true
  fi
  if [[ "$timer_active" == active ]]; then
    systemctl start aichat-security-monitor.timer >/dev/null 2>&1 || true
  fi
  if [[ "$config_path_enabled" == enabled ]]; then
    systemctl enable aichat-config-watch.path >/dev/null 2>&1 || true
  fi
  if [[ "$config_path_active" == active ]]; then
    systemctl start aichat-config-watch.path >/dev/null 2>&1 || true
  fi
  if [[ "$restore_timer_enabled" == enabled ]]; then
    systemctl enable aichat-restore-drill.timer >/dev/null 2>&1 || true
  fi
  if [[ "$restore_timer_active" == active ]]; then
    systemctl start aichat-restore-drill.timer >/dev/null 2>&1 || true
  fi
  rm -rf --one-file-system -- "$temporary"
  exit "$status"
}
trap 'rollback "$?"' ERR
trap 'rollback 130' INT TERM

systemctl stop aichat-security-monitor.timer aichat-security-monitor.service
systemctl stop aichat-config-watch.path aichat-config-watch.service \
  >/dev/null 2>&1 || true
if systemctl is-active --quiet aichat-restore-drill.service; then
  echo 'ERROR: refusing installation while the restore drill is running' >&2
  false
fi
systemctl stop aichat-restore-drill.timer >/dev/null 2>&1 || true
install -d -o root -g root -m 0755 -- /etc/sysusers.d
install -o root -g root -m 0644 -- "$SOURCE_SYSUSERS" "$TARGET_SYSUSERS"
systemd-sysusers "$TARGET_SYSUSERS"
monitor_uid="$(id -u "$MONITOR_USER")"
monitor_gid="$(id -g "$MONITOR_USER")"
[[ "$(getent passwd "$MONITOR_USER" | cut -d: -f7)" == '/usr/sbin/nologin' ]] || {
  echo 'ERROR: monitor identity must use nologin' >&2
  false
}

install -o root -g root -m 0755 -- "$SOURCE_MONITOR" "$TARGET_MONITOR"
install -o root -g root -m 0644 -- "$SOURCE_SERVICE" "$TARGET_SERVICE"
install -o root -g root -m 0644 -- "$SOURCE_TIMER" "$TARGET_TIMER"
install -o root -g root -m 0644 -- "$SOURCE_CONFIG_SERVICE" "$TARGET_CONFIG_SERVICE"
install -o root -g root -m 0644 -- "$SOURCE_CONFIG_PATH" "$TARGET_CONFIG_PATH"
install -o root -g root -m 0755 -- "$SOURCE_RESTORE_DRILL" "$TARGET_RESTORE_DRILL"
install -o root -g root -m 0644 -- "$SOURCE_RESTORE_SERVICE" "$TARGET_RESTORE_SERVICE"
install -o root -g root -m 0644 -- "$SOURCE_RESTORE_TIMER" "$TARGET_RESTORE_TIMER"
cmp --silent -- "$SOURCE_MONITOR" "$TARGET_MONITOR"
cmp --silent -- "$SOURCE_SERVICE" "$TARGET_SERVICE"
cmp --silent -- "$SOURCE_TIMER" "$TARGET_TIMER"
cmp --silent -- "$SOURCE_CONFIG_SERVICE" "$TARGET_CONFIG_SERVICE"
cmp --silent -- "$SOURCE_CONFIG_PATH" "$TARGET_CONFIG_PATH"
cmp --silent -- "$SOURCE_RESTORE_DRILL" "$TARGET_RESTORE_DRILL"
cmp --silent -- "$SOURCE_RESTORE_SERVICE" "$TARGET_RESTORE_SERVICE"
cmp --silent -- "$SOURCE_RESTORE_TIMER" "$TARGET_RESTORE_TIMER"

# The dedicated identity may traverse only the shared backup parent, list/stat
# this application's backup directory, and read only the privacy-minimized
# restore status. Mode-0600 database dumps deliberately receive no ACL.
setfacl -m "u:$MONITOR_USER:--x" -- "$BACKUP_PARENT"
setfacl -m "u:$MONITOR_USER:r-x" -- "$BACKUP_DIR"
setfacl -m "u:$MONITOR_USER:r--" -- "$RESTORE_LOG"
chown "$monitor_uid:$monitor_gid" -- "$STATE_DIR"
chmod 0700 -- "$STATE_DIR"
if [[ -f "$STATE_FILE" ]]; then
  chown "$monitor_uid:$monitor_gid" -- "$STATE_FILE"
  chmod 0600 -- "$STATE_FILE"
fi

systemctl daemon-reload
systemctl enable --now aichat-config-watch.path
systemctl enable --now aichat-security-monitor.timer
systemctl enable --now aichat-restore-drill.timer
systemctl start aichat-restore-drill.service
[[ "$(systemctl show aichat-restore-drill.service -p Result --value)" == success ]]
[[ "$(systemctl show aichat-restore-drill.service -p ExecMainStatus --value)" == 0 ]]
systemctl start aichat-security-monitor.service
[[ "$(systemctl show aichat-security-monitor.service -p Result --value)" == success ]]
[[ "$(systemctl show aichat-security-monitor.service -p ExecMainStatus --value)" == 0 ]]
[[ "$(systemctl show aichat-security-monitor.service -p User --value)" == "$MONITOR_USER" ]]
[[ "$(systemctl is-enabled aichat-config-watch.path)" == enabled ]]
[[ "$(systemctl is-active aichat-config-watch.path)" == active ]]
[[ "$(systemctl is-enabled aichat-restore-drill.timer)" == enabled ]]
[[ "$(systemctl is-active aichat-restore-drill.timer)" == active ]]
[[ "$(stat -c '%u:%g:%a' -- "$STATE_DIR")" == "$monitor_uid:$monitor_gid:700" ]]
if [[ -f "$STATE_FILE" ]]; then
  [[ "$(stat -c '%u:%g:%a' -- "$STATE_FILE")" == "$monitor_uid:$monitor_gid:600" ]]
  runuser --user "$MONITOR_USER" -- python3 -c '
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    state = json.load(handle)
if state.get("active"):
    raise SystemExit("monitor reported an active issue")
' "$STATE_FILE"
fi
latest_dump="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'nvidia_db_*.sql.gz' \
  -printf '%T@ %p\n' | sort -n | tail -n 1 | cut -d' ' -f2-)"
[[ -n "$latest_dump" ]]
if runuser --user "$MONITOR_USER" -- python3 -c '
from pathlib import Path
import sys
Path(sys.argv[1]).open("rb").read(1)
' "$latest_dump" >/dev/null 2>&1; then
  echo 'ERROR: dedicated monitor can read a private database dump' >&2
  false
fi
runuser --user "$MONITOR_USER" -- python3 -c '
from pathlib import Path
import sys
Path(sys.argv[1]).open("rb").read(1)
' "$RESTORE_LOG" >/dev/null

completed=1
trap - ERR INT TERM
rm -rf --one-file-system -- "$temporary"
echo "Security monitor installed under $MONITOR_USER; database dumps remain unreadable."
