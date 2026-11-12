#!/usr/bin/env bash
# Atomically change AI generation and registration containment controls, with
# automatic runtime-config rollback and a self-restoring production exercise.
set -euo pipefail
umask 077

DOMAIN='aichat.micutu.com'
RUNTIME_DIR='/home/micu/nvidia/backend'
ENV_FILE="$RUNTIME_DIR/.env"
APP_DIR='/opt/aichat-backend-current'
PYTHON='/opt/aichat-python-current/bin/python'
SERVICE='aichat-backend.service'
WATCHER='aichat-config-watch.path'
CONTROL_TOOL='/usr/local/libexec/aichat-incident-control-render'
SECRET_CHECK='/usr/local/libexec/aichat-runtime-secret-check'
CREDENTIAL_CHECK='/usr/local/libexec/aichat-application-credential-check'
CREDENTIAL_DIR='/etc/aichat/application-credentials'
RELEASE_LOCK='/run/aichat-release-operation.lock'
CONTROL_LOCK='/run/aichat-incident-controls.lock'

operation=''
generation=''
registration=''
execute_mode=''
temporary=''
runtime_next=''
configuration_switched=0
completed=0
watcher_was_active=0
original_generation=''
original_registration=''

usage() {
  cat >&2 <<'EOF'
Usage:
  sudo /usr/local/sbin/aichat-incident-controls --contain --dry-run|--apply
  sudo /usr/local/sbin/aichat-incident-controls \
    --generation enabled|disabled --registration open|invite|closed --dry-run|--apply
  sudo /usr/local/sbin/aichat-incident-controls --exercise --apply
EOF
}

origin_curl() {
  curl --silent --show-error --max-time 5 \
    --resolve "$DOMAIN:443:127.0.0.1" "$@"
}

full_probes() {
  local media_code private_code
  origin_curl --fail --output /dev/null "https://$DOMAIN/api/health/" || return 1
  media_code="$(origin_curl --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/media/incident-control-probe")" || return 1
  [[ "$media_code" == '404' ]] || return 1
  private_code="$(origin_curl --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/api/conversations/")" || return 1
  [[ "$private_code" == '403' ]]
}

wait_for_health() {
  local attempt
  for ((attempt = 1; attempt <= 45; attempt++)); do
    if systemctl is-active --quiet "$SERVICE" && full_probes 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

restore_watcher() {
  if (( watcher_was_active )); then
    systemctl start "$WATCHER"
  fi
}

cleanup_temporary() {
  [[ -n "$runtime_next" ]] && unlink -- "$runtime_next" 2>/dev/null || true
  if [[ -n "$temporary" && "$temporary" == /run/aichat-incident-controls.* \
    && -d "$temporary" && ! -L "$temporary" ]]; then
    rm -rf --one-file-system -- "$temporary"
  fi
}

restore_snapshot() {
  local rollback_next
  [[ -n "$temporary" && -f "$temporary/env.before" \
    && ! -L "$temporary/env.before" ]] || return 1
  rollback_next="$RUNTIME_DIR/.incident-controls-rollback-$$"
  install -o micu -g aichat -m 0640 -- "$temporary/env.before" "$rollback_next"
  mv -Tf -- "$rollback_next" "$ENV_FILE"
}

rollback() {
  local status="${1:-1}"
  trap - ERR INT TERM EXIT
  if (( completed )); then
    return
  fi
  echo 'ERROR: incident-control change failed; restoring prior runtime configuration' >&2
  if (( configuration_switched )); then
    restore_snapshot || true
    systemctl restart "$SERVICE" >/dev/null 2>&1 || true
    if ! wait_for_health >/dev/null 2>&1; then
      echo 'CRITICAL: incident-control rollback did not restore service health' >&2
    fi
  fi
  restore_watcher >/dev/null 2>&1 || true
  cleanup_temporary
  exit "$status"
}

preflight_controls() {
  local desired_generation="$1" desired_registration="$2"
  runuser --user aichat -- env --chdir="$APP_DIR" \
    AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1 \
    AI_GENERATION_ENABLED="$([[ "$desired_generation" == enabled ]] && echo true || echo false)" \
    REGISTRATION_MODE="$desired_registration" \
    "$PYTHON" manage.py check --deploy
}

runtime_controls() {
  runuser --user aichat -- env --chdir="$APP_DIR" \
    AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" manage.py shell --no-imports -c \
    "from django.conf import settings; print(('enabled' if settings.AI_GENERATION_ENABLED else 'disabled') + '|' + settings.REGISTRATION_MODE)"
}

activate_controls() {
  local desired_generation="$1" desired_registration="$2" stage actual
  stage="$temporary/env.stage.$RANDOM"
  "$CONTROL_TOOL" --env-file "$ENV_FILE" --stage-output "$stage" \
    --generation "$desired_generation" --registration "$desired_registration"
  runtime_next="$RUNTIME_DIR/.incident-controls-next-$$"
  install -o micu -g aichat -m 0640 -- "$stage" "$runtime_next"
  unlink -- "$stage"
  mv -Tf -- "$runtime_next" "$ENV_FILE"
  runtime_next=''
  configuration_switched=1

  "$SECRET_CHECK" --runtime-dir "$RUNTIME_DIR" --owner micu --group aichat
  "$PYTHON" "$CREDENTIAL_CHECK" \
    --env-file "$ENV_FILE" --credential-dir "$CREDENTIAL_DIR" --admin-user micu
  "$CONTROL_TOOL" --env-file "$ENV_FILE" --check \
    --generation "$desired_generation" --registration "$desired_registration"
  systemctl restart "$SERVICE"
  wait_for_health
  actual="$(runtime_controls)"
  [[ "$actual" == "$desired_generation|$desired_registration" ]] || {
    echo 'ERROR: restarted backend did not load the requested incident controls' >&2
    return 1
  }
}

while (( $# )); do
  case "$1" in
    --contain|--exercise)
      [[ -z "$operation" ]] || { usage; exit 2; }
      operation="${1#--}"
      shift
      ;;
    --generation)
      [[ $# -ge 2 && -z "$generation" ]] || { usage; exit 2; }
      generation="$2"
      shift 2
      ;;
    --registration)
      [[ $# -ge 2 && -z "$registration" ]] || { usage; exit 2; }
      registration="$2"
      shift 2
      ;;
    --apply|--dry-run)
      [[ -z "$execute_mode" ]] || { usage; exit 2; }
      execute_mode="${1#--}"
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [[ "$operation" == contain ]]; then
  [[ -z "$generation" && -z "$registration" ]] || { usage; exit 2; }
  generation='disabled'
  registration='closed'
elif [[ "$operation" == exercise ]]; then
  [[ -z "$generation" && -z "$registration" && "$execute_mode" == apply ]] \
    || { usage; exit 2; }
elif [[ -z "$operation" ]]; then
  [[ -n "$generation" && -n "$registration" ]] || { usage; exit 2; }
else
  usage
  exit 2
fi
[[ "$execute_mode" == apply || "$execute_mode" == dry-run ]] || { usage; exit 2; }

if (( EUID != 0 )); then
  echo 'ERROR: incident controls must run as root' >&2
  exit 1
fi
for command in cp curl date flock install logger mapfile mktemp mv readlink rm \
  runuser sleep stat systemctl unlink; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
for target in "$CONTROL_TOOL" "$SECRET_CHECK" "$CREDENTIAL_CHECK"; do
  [[ -f "$target" && ! -L "$target" && -x "$target" \
    && "$(stat -c '%U:%G:%a' -- "$target")" == 'root:root:755' ]] || {
    echo 'ERROR: installed incident-control dependency is missing or unsafe' >&2
    exit 1
  }
done
resolved_app="$(readlink -f -- "$APP_DIR")"
[[ -x "$PYTHON" && -L "$APP_DIR" && -d "$resolved_app" \
  && ! -L "$resolved_app" \
  && "$resolved_app" == /opt/aichat-backend-releases/release-* ]] || {
  echo 'ERROR: active application runtime is missing or unsafe' >&2
  exit 1
}

exec 8>"$RELEASE_LOCK"
flock -n 8 || { echo 'ERROR: another release operation is running' >&2; exit 1; }
exec 9>"$CONTROL_LOCK"
flock -n 9 || { echo 'ERROR: another incident-control operation is running' >&2; exit 1; }

"$SECRET_CHECK" --runtime-dir "$RUNTIME_DIR" --owner micu --group aichat
"$PYTHON" "$CREDENTIAL_CHECK" \
  --env-file "$ENV_FILE" --credential-dir "$CREDENTIAL_DIR" --admin-user micu
mapfile -d '' -t current < <("$CONTROL_TOOL" --env-file "$ENV_FILE" --show0)
[[ "${#current[@]}" == 2 ]] || {
  echo 'ERROR: could not read current incident controls' >&2
  exit 1
}
original_generation="${current[0]}"
original_registration="${current[1]}"

if [[ "$operation" == exercise ]]; then
  generation='disabled'
  registration='closed'
  [[ "$original_generation" == enabled && "$original_registration" != closed ]] || {
    echo 'ERROR: exercise requires generation enabled and registration not closed' >&2
    exit 1
  }
  active_requests="$(runuser --user aichat -- env --chdir="$APP_DIR" \
    AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1 \
    "$PYTHON" manage.py shell --no-imports -c \
    "from chat.models import GenerationRequest; print(GenerationRequest.objects.filter(state__in=GenerationRequest.ACTIVE_STATES).count())")"
  [[ "$active_requests" == 0 ]] || {
    echo 'ERROR: refusing exercise while a generation request is active' >&2
    exit 1
  }
fi

temporary="$(mktemp -d /run/aichat-incident-controls.XXXXXX)"
cp -a -- "$ENV_FILE" "$temporary/env.before"

if [[ "$execute_mode" == dry-run ]]; then
  stage="$temporary/env.dry-run"
  "$CONTROL_TOOL" --env-file "$ENV_FILE" --stage-output "$stage" \
    --generation "$generation" --registration "$registration"
  "$CONTROL_TOOL" --env-file "$stage" --check \
    --generation "$generation" --registration "$registration"
  printf 'Dry run passed: generation %s -> %s; registration %s -> %s\n' \
    "$original_generation" "$generation" "$original_registration" "$registration"
  cleanup_temporary
  exit 0
fi

trap 'rollback "$?"' ERR EXIT
trap 'rollback 130' INT TERM
preflight_controls "$generation" "$registration"
if systemctl is-active --quiet "$WATCHER"; then
  watcher_was_active=1
  systemctl stop "$WATCHER"
fi
systemctl stop aichat-config-watch.service >/dev/null 2>&1 || true

contain_started="$(date +%s)"
activate_controls "$generation" "$registration"
contain_seconds="$(( $(date +%s) - contain_started ))"
logger --id="$$" --priority=authpriv.notice --tag=aichat-incident-controls \
  "event=incident_controls_applied generation=$generation registration=$registration"

if [[ "$operation" == exercise ]]; then
  restore_started="$(date +%s)"
  restore_snapshot
  systemctl restart "$SERVICE"
  wait_for_health
  "$CONTROL_TOOL" --env-file "$ENV_FILE" --check \
    --generation "$original_generation" --registration "$original_registration"
  actual="$(runtime_controls)"
  [[ "$actual" == "$original_generation|$original_registration" ]]
  restore_seconds="$(( $(date +%s) - restore_started ))"
  logger --id="$$" --priority=authpriv.notice --tag=aichat-incident-controls \
    "event=incident_controls_exercise_restored generation=$original_generation registration=$original_registration"
  printf 'Incident-control exercise passed: contain_seconds=%s restore_seconds=%s\n' \
    "$contain_seconds" "$restore_seconds"
else
  printf 'Incident controls applied: generation=%s registration=%s restart_seconds=%s\n' \
    "$generation" "$registration" "$contain_seconds"
fi

restore_watcher
if (( watcher_was_active )); then
  systemctl is-active --quiet "$WATCHER"
fi
cleanup_temporary
completed=1
trap - ERR INT TERM EXIT
