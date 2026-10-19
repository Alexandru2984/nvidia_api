#!/usr/bin/env bash
# Exercise one immutable production rollback and always restore the original
# release. No migrations, provider requests, or application data writes occur.
set -euo pipefail
umask 077

DOMAIN='aichat.micutu.com'
RUNTIME_DIR='/home/micu/nvidia/backend'
BACKEND_ROOT='/opt/aichat-backend-releases'
BACKEND_LIVE='/opt/aichat-backend-current'
PYTHON_ROOT='/opt/aichat-python-envs'
PYTHON_LIVE='/opt/aichat-python-current'
FRONTEND_ROOT='/var/www/aichat-releases'
FRONTEND_LIVE='/var/www/aichat.micutu.com'
REPO_DIR='/home/micu/nvidia'
SERVICE='aichat-backend.service'
SBOM_TOOL='/home/micu/nvidia/scripts/generate_python_sbom.py'
PROVENANCE_TOOL='/home/micu/nvidia/scripts/release_provenance.py'
SYSTEM_PYTHON='/usr/bin/python3.14'
LOCK_FILE='/run/aichat-release-operation.lock'

family=''
preflight_only=0
release_root=''
live_path=''
original_target=''
rollback_target=''
temporary_link=''
restore_required=0
original_pid=''
rollback_pid=''
restored_pid=''
original_restarts=''

usage() {
  echo 'Usage: sudo scripts/release_rollback_drill.sh --family backend|python|frontend [--preflight-only]' >&2
}

origin_code() {
  curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}' \
    --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN$1"
}

full_probes() {
  local path expected actual

  while read -r path expected; do
    actual="$(origin_code "$path")" || return 1
    if [[ "$actual" != "$expected" ]]; then
      echo "ERROR: origin probe $path returned $actual, expected $expected" >&2
      return 1
    fi
  done <<'EOF'
/ 200
/api/health/ 200
/.well-known/security.txt 200
/media/rollback-drill-probe 404
/.env 403
/.git/config 403
/api/conversations/ 403
EOF
}

target_for_pid() {
  local pid="$1"

  if [[ "$family" == 'backend' ]]; then
    readlink -f -- "/proc/$pid/cwd"
  else
    readlink -f -- "/proc/$pid/exe"
  fi
}

expected_process_target() {
  local release="$1"

  if [[ "$family" == 'backend' ]]; then
    printf '%s\n' "$release"
  else
    printf '%s\n' "$release/bin/python"
  fi
}

wait_for_target() {
  local expected_release="$1"
  local attempt pid actual expected

  expected="$(expected_process_target "$expected_release")"
  for ((attempt = 1; attempt <= 60; attempt++)); do
    if systemctl is-active --quiet "$SERVICE"; then
      pid="$(systemctl show --property=MainPID --value "$SERVICE")"
      if [[ "$pid" =~ ^[1-9][0-9]*$ ]]; then
        actual="$(target_for_pid "$pid" 2>/dev/null || true)"
        if [[ "$actual" == "$expected" ]] && full_probes 2>/dev/null; then
          printf '%s\n' "$pid"
          return 0
        fi
      fi
    fi
    sleep 1
  done
  echo "ERROR: service did not become healthy on $expected_release within 60 seconds" >&2
  return 1
}

atomic_switch() {
  local target="$1"

  temporary_link="$live_path.drill.$$.${RANDOM}"
  if [[ -e "$temporary_link" || -L "$temporary_link" ]]; then
    echo "ERROR: temporary activation path already exists: $temporary_link" >&2
    return 1
  fi
  ln -s -- "$target" "$temporary_link"
  mv -Tf -- "$temporary_link" "$live_path"
  temporary_link=''
}

restore_original() {
  atomic_switch "$original_target"
  if [[ "$family" == 'frontend' ]]; then
    full_probes
  else
    systemctl restart "$SERVICE"
    restored_pid="$(wait_for_target "$original_target")"
    if [[ "$restored_pid" == "$rollback_pid" && -n "$rollback_pid" ]]; then
      echo 'ERROR: service PID did not change while restoring the original release' >&2
      return 1
    fi
  fi
  restore_required=0
}

cleanup() {
  local status="$?"

  trap - EXIT HUP INT TERM
  if [[ -n "$temporary_link" && -L "$temporary_link" ]]; then
    unlink -- "$temporary_link" || status=1
  fi
  if (( restore_required )) && [[ -n "$original_target" ]]; then
    echo 'Restoring the original release after an interrupted or failed drill...' >&2
    if ! restore_original >/dev/null; then
      echo 'CRITICAL: automatic drill restoration did not restore verified service health' >&2
      status=1
    else
      restore_required=0
    fi
  fi
  exit "$status"
}

git_read() {
  git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" "$@"
}

validate_release_tree() {
  local release="$1"

  [[ -d "$release" && ! -L "$release" ]] || {
    echo "ERROR: unsafe release directory: $release" >&2
    return 1
  }
  [[ "$(stat -c '%u:%g' -- "$release")" == '0:0' ]] || {
    echo "ERROR: release directory is not root-owned: $release" >&2
    return 1
  }
  if find "$release" -xdev \( -type l -o ! -type d -a ! -type f \) -print -quit | grep -q .; then
    echo "ERROR: release contains a symlink or special file: $release" >&2
    return 1
  fi
  if find "$release" -xdev \( ! -user root -o ! -group root -o -perm /022 \) -print -quit \
    | grep -q .; then
    echo "ERROR: release ownership or write permissions are unsafe: $release" >&2
    return 1
  fi
  [[ -f "$release/.release-manifest.sha256" \
    && ! -L "$release/.release-manifest.sha256" ]] || {
    echo "ERROR: release manifest is missing or unsafe: $release" >&2
    return 1
  }
  (cd "$release" && sha256sum --check --strict .release-manifest.sha256 >/dev/null)
}

validate_commit_marker() {
  local release="$1" commit

  [[ -f "$release/.release-commit" && ! -L "$release/.release-commit" ]] || {
    echo "ERROR: release commit marker is missing or unsafe: $release" >&2
    return 1
  }
  commit="$(tr -d '\n' < "$release/.release-commit")"
  [[ "$commit" =~ ^[0-9a-f]{40,64}$ ]] || {
    echo "ERROR: invalid release commit marker: $release" >&2
    return 1
  }
}

validate_release_provenance() {
  local release="$1" require_provenance="$2"

  if [[ -e "$release/.release-manifest.ed25519" \
    || -L "$release/.release-manifest.ed25519" \
    || -e "$release/.release-signing-key-id" \
    || -L "$release/.release-signing-key-id" ]]; then
    "$PROVENANCE_TOOL" verify --family "$family" --release "$release"
  elif (( require_provenance )); then
    echo "ERROR: active $family release has no signed provenance: $release" >&2
    return 1
  else
    echo "NOTICE: rollback $family release predates signed provenance: $release" >&2
  fi
}

validate_python_release() {
  local release="$1" commit

  validate_release_tree "$release"
  validate_commit_marker "$release"
  for artifact in .release-requirements.lock .release-requirements.sha256 .release-sbom.cdx.json; do
    [[ -f "$release/$artifact" && ! -L "$release/$artifact" ]] || {
      echo "ERROR: required Python release artifact is missing or unsafe: $release/$artifact" >&2
      return 1
    }
  done
  [[ -f "$release/bin/python" && -x "$release/bin/python" ]] || {
    echo "ERROR: Python release interpreter is missing or not executable: $release" >&2
    return 1
  }
  (cd "$release" && sha256sum --check --strict .release-requirements.sha256 >/dev/null)
  commit="$(tr -d '\n' < "$release/.release-commit")"
  "$SYSTEM_PYTHON" "$SBOM_TOOL" "$release/.release-requirements.lock" \
    --commit "$commit" --check "$release/.release-sbom.cdx.json"
  runuser --user aichat -- env HOME=/nonexistent PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 \
    "$release/bin/python" -m pip check
}

validate_frontend_release() {
  local release="$1" require_provenance="$2" commit frontend_tree expected_tree

  validate_release_tree "$release"
  if find "$release" -xdev -type d ! -perm 0755 -print -quit | grep -q . \
    || find "$release" -xdev -type f ! -perm 0644 -print -quit | grep -q .; then
    echo "ERROR: frontend release has an unexpected file mode: $release" >&2
    return 1
  fi
  if [[ ! -e "$release/.release-commit" && ! -L "$release/.release-commit" \
    && ! -e "$release/.release-frontend-tree" \
    && ! -L "$release/.release-frontend-tree" ]]; then
    if (( require_provenance )); then
      echo "ERROR: active frontend release predates required provenance: $release" >&2
      return 1
    fi
    echo "NOTICE: rollback frontend release predates commit/tree markers: $release" >&2
    return 0
  fi
  validate_commit_marker "$release"
  [[ -f "$release/.release-frontend-tree" \
    && ! -L "$release/.release-frontend-tree" ]] || {
    echo "ERROR: frontend tree marker is missing or unsafe: $release" >&2
    return 1
  }
  frontend_tree="$(tr -d '\n' < "$release/.release-frontend-tree")"
  [[ "$frontend_tree" =~ ^[0-9a-f]{40,64}$ ]] || {
    echo "ERROR: invalid frontend tree marker: $release" >&2
    return 1
  }
  commit="$(tr -d '\n' < "$release/.release-commit")"
  git_read cat-file -e "$commit^{commit}" 2>/dev/null || {
    echo "ERROR: frontend release commit is not available locally: $release" >&2
    return 1
  }
  expected_tree="$(git_read rev-parse --verify "$commit:frontend")"
  [[ "$frontend_tree" == "$expected_tree" ]] || {
    echo "ERROR: frontend release tree does not match its commit: $release" >&2
    return 1
  }
}

select_rollback_target() {
  local candidate name selected=''

  while IFS= read -r -d '' candidate; do
    name="${candidate##*/}"
    [[ "$name" =~ ^release-[0-9]{8}T[0-9]{6}_[0-9]+$ ]] || continue
    [[ "$candidate" == "$original_target" ]] && continue
    [[ -d "$candidate" && ! -L "$candidate" ]] || continue
    if [[ -z "$selected" || "$candidate" > "$selected" ]]; then
      selected="$candidate"
    fi
  done < <(find "$release_root" -mindepth 1 -maxdepth 1 -print0)

  [[ -n "$selected" ]] || {
    echo "ERROR: no inactive rollback release exists below $release_root" >&2
    return 1
  }
  printf '%s\n' "$selected"
}

preflight_backend() {
  local imported
  local command=(
    runuser --user aichat -- env --chdir="$rollback_target"
    AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1
    "$PYTHON_LIVE/bin/python"
  )

  "${command[@]}" manage.py check --deploy
  "${command[@]}" manage.py migrate --check
  imported="$("${command[@]}" -c \
    'from pathlib import Path; import chat; print(Path(chat.__file__).resolve())')"
  [[ "$imported" == "$rollback_target"/* ]] || {
    echo 'ERROR: rollback preflight imported backend code outside the candidate release' >&2
    return 1
  }
}

preflight_python() {
  local backend_target imported
  local command

  backend_target="$(readlink -f -- "$BACKEND_LIVE")"
  [[ "$backend_target" == "$BACKEND_ROOT"/* && -d "$backend_target" \
    && ! -L "$backend_target" ]] || {
    echo 'ERROR: active backend release leaves its trusted root' >&2
    return 1
  }
  validate_release_tree "$backend_target"
  validate_commit_marker "$backend_target"
  cmp --silent -- "$original_target/.release-requirements.lock" \
    "$rollback_target/.release-requirements.lock" || {
    echo 'ERROR: refusing to drill between Python environments with different requirement locks' >&2
    return 1
  }
  command=(
    runuser --user aichat -- env --chdir="$backend_target"
    AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1
    "$rollback_target/bin/python"
  )
  "${command[@]}" manage.py check --deploy
  "${command[@]}" manage.py migrate --check
  "${command[@]}" -c 'import django, gunicorn, psycopg2, cryptography, lxml'
  imported="$("${command[@]}" -c \
    'from pathlib import Path; import chat; print(Path(chat.__file__).resolve())')"
  [[ "$imported" == "$backend_target"/* ]] || {
    echo 'ERROR: Python rollback preflight imported code outside the active backend release' >&2
    return 1
  }
}

if (( EUID != 0 )); then
  echo 'ERROR: release rollback drill must run as root' >&2
  exit 1
fi
while (( $# )); do
  case "$1" in
    --family)
      [[ $# -ge 2 ]] || { usage; exit 2; }
      family="$2"
      shift 2
      ;;
    --preflight-only)
      preflight_only=1
      shift
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done
case "$family" in
  backend)
    release_root="$BACKEND_ROOT"
    live_path="$BACKEND_LIVE"
    ;;
  python)
    release_root="$PYTHON_ROOT"
    live_path="$PYTHON_LIVE"
    ;;
  frontend)
    release_root="$FRONTEND_ROOT"
    live_path="$FRONTEND_LIVE"
    ;;
  *)
    usage
    exit 2
    ;;
esac

for command in curl find flock git grep ln mv readlink sha256sum stat systemctl; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
[[ -x "$PROVENANCE_TOOL" && ! -L "$PROVENANCE_TOOL" ]] || {
  echo 'ERROR: release-provenance tool is missing or unsafe' >&2
  exit 1
}
if [[ "$family" != 'frontend' ]]; then
  for command in cmp runuser "$SYSTEM_PYTHON"; do
    command -v "$command" >/dev/null || {
      echo "ERROR: required command is missing: $command" >&2
      exit 1
    }
  done
fi
if [[ "$family" == 'python' ]]; then
  [[ -f "$SBOM_TOOL" && ! -L "$SBOM_TOOL" ]] || {
    echo 'ERROR: SBOM validation tool is missing or unsafe' >&2
    exit 1
  }
fi
[[ -d "$release_root" && ! -L "$release_root" \
  && "$(stat -c '%u:%g' -- "$release_root")" == '0:0' ]] || {
  echo "ERROR: release root is missing, linked, or not root-owned: $release_root" >&2
  exit 1
}
[[ -L "$live_path" ]] || {
  echo "ERROR: active release path is not a symlink: $live_path" >&2
  exit 1
}

exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'ERROR: another release operation is running' >&2; exit 1; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

original_target="$(readlink -f -- "$live_path")"
direct_target="$(readlink -- "$live_path")"
[[ "$original_target" == "$release_root"/* && "$direct_target" == "$original_target" \
  && -d "$original_target" && ! -L "$original_target" ]] || {
  echo 'ERROR: active release symlink is indirect or leaves its trusted release root' >&2
  exit 1
}
rollback_target="$(select_rollback_target)"

case "$family" in
  backend)
    validate_release_tree "$original_target"
    validate_commit_marker "$original_target"
    validate_release_tree "$rollback_target"
    validate_commit_marker "$rollback_target"
    preflight_backend
    ;;
  python)
    validate_python_release "$original_target"
    validate_python_release "$rollback_target"
    preflight_python
    ;;
  frontend)
    validate_frontend_release "$original_target" 1
    validate_frontend_release "$rollback_target" 0
    ;;
esac
validate_release_provenance "$original_target" 1
validate_release_provenance "$rollback_target" 0

systemctl is-active --quiet "$SERVICE" || {
  echo 'ERROR: refusing drill while the backend service is not active' >&2
  exit 1
}
full_probes
original_pid="$(systemctl show --property=MainPID --value "$SERVICE")"
[[ "$original_pid" =~ ^[1-9][0-9]*$ ]] || {
  echo 'ERROR: backend service has no valid main PID' >&2
  exit 1
}
if [[ "$family" != 'frontend' ]]; then
  [[ "$(target_for_pid "$original_pid")" == "$(expected_process_target "$original_target")" ]] || {
    echo 'ERROR: running process does not use the active release target' >&2
    exit 1
  }
fi
original_restarts="$(systemctl show --property=NRestarts --value "$SERVICE")"
[[ "$original_restarts" =~ ^[0-9]+$ ]] || {
  echo 'ERROR: backend service has no valid restart counter' >&2
  exit 1
}

printf 'Rollback drill preflight passed: family=%s active=%s candidate=%s pid=%s\n' \
  "$family" "$original_target" "$rollback_target" "$original_pid"
if (( preflight_only )); then
  exit 0
fi

started_at="$SECONDS"
restore_required=1
atomic_switch "$rollback_target"
if [[ "$family" == 'frontend' ]]; then
  [[ "$(readlink -- "$live_path")" == "$rollback_target" ]] || {
    echo 'ERROR: frontend rollback target was not activated exactly' >&2
    exit 1
  }
  full_probes
else
  systemctl restart "$SERVICE"
  rollback_pid="$(wait_for_target "$rollback_target")"
  [[ "$rollback_pid" != "$original_pid" ]] || {
    echo 'ERROR: service PID did not change during rollback activation' >&2
    exit 1
  }
fi
rollback_seconds=$((SECONDS - started_at))

restore_started_at="$SECONDS"
restore_original
restore_seconds=$((SECONDS - restore_started_at))
[[ "$(readlink -- "$live_path")" == "$original_target" ]] || {
  echo 'ERROR: original release symlink was not restored exactly' >&2
  exit 1
}
final_restarts="$(systemctl show --property=NRestarts --value "$SERVICE")"
[[ "$final_restarts" == "$original_restarts" ]] || {
  echo "ERROR: automatic restart counter changed from $original_restarts to $final_restarts" >&2
  exit 1
}
if [[ "$family" == 'frontend' ]]; then
  final_pid="$(systemctl show --property=MainPID --value "$SERVICE")"
  [[ "$final_pid" == "$original_pid" ]] || {
    echo 'ERROR: backend PID changed during the static frontend drill' >&2
    exit 1
  }
fi
full_probes

if [[ "$family" == 'frontend' ]]; then
  printf 'Rollback drill passed: family=%s rollback_seconds=%s restore_seconds=%s active=%s\n' \
    "$family" "$rollback_seconds" "$restore_seconds" "$original_target"
else
  printf 'Rollback drill passed: family=%s rollback_pid=%s restored_pid=%s rollback_seconds=%s restore_seconds=%s active=%s\n' \
    "$family" "$rollback_pid" "$restored_pid" "$rollback_seconds" "$restore_seconds" \
    "$original_target"
fi
