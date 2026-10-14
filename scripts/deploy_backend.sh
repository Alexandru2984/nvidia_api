#!/usr/bin/env bash
# Stage committed backend code as a root-owned release, switch atomically, and
# restore both code and systemd configuration if post-switch probes fail.
set -euo pipefail
umask 022

DOMAIN='aichat.micutu.com'
REPO_DIR='/home/micu/nvidia'
RUNTIME_DIR='/home/micu/nvidia/backend'
VENV_DIR='/opt/aichat-python-current'
RELEASE_ROOT='/opt/aichat-backend-releases'
LIVE_PATH='/opt/aichat-backend-current'
SERVICE='aichat-backend.service'
RETENTION_TOOL="$REPO_DIR/scripts/archive_release_retention.py"
LOCK_FILE='/run/aichat-release-operation.lock'
BOOTSTRAP=0

UNIT_SOURCES=(
  'ops/systemd/aichat-backend.service'
  'ops/systemd/hardening.conf'
  'ops/systemd/aichat-maintenance.service'
  'ops/systemd/aichat-model-probe.service'
  'ops/systemd/aichat-model-probe.timer'
)
UNIT_TARGETS=(
  '/etc/systemd/system/aichat-backend.service'
  '/etc/systemd/system/aichat-backend.service.d/hardening.conf'
  '/etc/systemd/system/aichat-maintenance.service'
  '/etc/systemd/system/aichat-model-probe.service'
  '/etc/systemd/system/aichat-model-probe.timer'
)

previous=''
release=''
staging=''
next_link=''
temporary=''
activation_started=0
units_backed_up=0

usage() {
  echo 'Usage: sudo scripts/deploy_backend.sh [--bootstrap]' >&2
}

git_read() {
  git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" "$@"
}

origin_curl() {
  curl --silent --show-error --max-time 5 --resolve "$DOMAIN:443:127.0.0.1" "$@"
}

health_ready() {
  origin_curl --fail --output /dev/null "https://$DOMAIN/api/health/"
}

full_probes() {
  local media_code private_code

  health_ready || return 1
  media_code="$(origin_curl --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/media/backend-deploy-probe")" || return 1
  [[ "$media_code" == '404' ]] || return 1
  private_code="$(origin_curl --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/api/conversations/")" || return 1
  [[ "$private_code" == '403' ]] || return 1
}

wait_for_release() {
  local attempt main_pid process_cwd

  for ((attempt = 1; attempt <= 45; attempt++)); do
    if systemctl is-active --quiet "$SERVICE" && health_ready 2>/dev/null; then
      main_pid="$(systemctl show --property=MainPID --value "$SERVICE")"
      if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
        process_cwd="$(readlink -f -- "/proc/$main_pid/cwd")"
        if [[ "$process_cwd" == "$release" ]]; then
          full_probes
          return
        fi
      fi
    fi
    sleep 1
  done
  return 1
}

backup_units() {
  local index target backup

  install -d -o root -g root -m 0700 "$temporary/units"
  for index in "${!UNIT_TARGETS[@]}"; do
    target="${UNIT_TARGETS[$index]}"
    backup="$temporary/units/$index"
    if [[ -f "$target" && ! -L "$target" ]]; then
      cp -a -- "$target" "$backup"
    elif [[ ! -e "$target" && ! -L "$target" ]]; then
      : > "$backup.missing"
    else
      echo "ERROR: unsafe installed unit target: $target" >&2
      return 1
    fi
  done
  units_backed_up=1
}

install_committed_units() {
  local index source target staged

  install -d -o root -g root -m 0755 '/etc/systemd/system/aichat-backend.service.d'
  install -d -o root -g root -m 0700 "$temporary/new-units"
  for index in "${!UNIT_SOURCES[@]}"; do
    source="${UNIT_SOURCES[$index]}"
    target="${UNIT_TARGETS[$index]}"
    staged="$temporary/new-units/$index"
    git_read show "$commit:$source" > "$staged"
    install -o root -g root -m 0644 -- "$staged" "$target"
  done
}

restore_units() {
  local index target backup

  (( units_backed_up )) || return 0
  for index in "${!UNIT_TARGETS[@]}"; do
    target="${UNIT_TARGETS[$index]}"
    backup="$temporary/units/$index"
    if [[ -f "$backup" ]]; then
      cp -a -- "$backup" "$target"
    elif [[ -f "$backup.missing" ]]; then
      unlink -- "$target" 2>/dev/null || true
    fi
  done
}

restore_previous_release() {
  local rollback_link

  if [[ -n "$next_link" && -L "$next_link" ]]; then
    unlink -- "$next_link"
  fi
  if [[ -n "$previous" ]]; then
    rollback_link="$LIVE_PATH.rollback.$stamp"
    ln -s -- "$previous" "$rollback_link"
    mv -Tf -- "$rollback_link" "$LIVE_PATH"
  elif [[ -L "$LIVE_PATH" ]]; then
    unlink -- "$LIVE_PATH"
  fi
}

handle_error() {
  local status="${1:-1}"

  trap - ERR INT TERM
  if (( activation_started )); then
    echo 'ERROR: backend activation failed; restoring systemd units and previous release' >&2
    restore_previous_release || true
    restore_units || true
    systemctl daemon-reload || true
    systemctl restart "$SERVICE" || true
    if ! health_ready >/dev/null 2>&1; then
      echo 'CRITICAL: automatic backend rollback did not restore health' >&2
    fi
  fi
  if [[ -n "$staging" && -d "$staging" ]]; then
    rm -rf --one-file-system -- "$staging"
  fi
  if [[ -n "$temporary" && -d "$temporary" ]]; then
    rm -rf --one-file-system -- "$temporary"
  fi
  exit "$status"
}

if [[ "${1:-}" == '--bootstrap' ]]; then
  BOOTSTRAP=1
  shift
fi
if (( $# != 0 )); then
  usage
  exit 2
fi
if (( EUID != 0 )); then
  echo 'ERROR: backend deployment must run as root' >&2
  exit 1
fi
for command in flock git tar sha256sum runuser curl systemctl readlink; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'ERROR: another release operation is running' >&2; exit 1; }
if [[ ! -d "$REPO_DIR/.git" || -L "$REPO_DIR/.git" ]]; then
  echo 'ERROR: repository metadata is missing or unsafe' >&2
  exit 1
fi
if [[ ! -x "$RETENTION_TOOL" || -L "$RETENTION_TOOL" ]]; then
  echo 'ERROR: release-retention tool is missing or unsafe' >&2
  exit 1
fi
if [[ ! -x "$VENV_DIR/bin/python" || ! -f "$VENV_DIR/.release-manifest.sha256" ]]; then
  echo 'ERROR: immutable production Python environment is incomplete' >&2
  exit 1
fi
if ! git_read diff --quiet -- || ! git_read diff --cached --quiet --; then
  echo 'ERROR: tracked worktree changes must be committed before deployment' >&2
  exit 1
fi

commit="$(git_read rev-parse --verify 'HEAD^{commit}')"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
  echo 'ERROR: could not resolve a full deployment commit' >&2
  exit 1
}

if [[ -L "$LIVE_PATH" ]]; then
  if (( BOOTSTRAP )); then
    echo 'ERROR: --bootstrap is valid only before the first atomic backend release' >&2
    exit 1
  fi
  previous="$(readlink -f -- "$LIVE_PATH")"
  if [[ "$previous" != "$RELEASE_ROOT"/* || ! -d "$previous" || -L "$previous" ]]; then
    echo 'ERROR: live backend symlink does not target the trusted release root' >&2
    exit 1
  fi
elif [[ -e "$LIVE_PATH" ]]; then
  echo 'ERROR: live backend path is not a symlink' >&2
  exit 1
elif (( ! BOOTSTRAP )); then
  echo 'ERROR: first deployment requires explicit --bootstrap' >&2
  exit 1
fi

systemctl is-active --quiet "$SERVICE" || {
  echo 'ERROR: refusing deployment while the backend service is not active' >&2
  exit 1
}
health_ready || {
  echo 'ERROR: refusing deployment while the origin health probe is failing' >&2
  exit 1
}

install -d -o root -g root -m 0755 "$RELEASE_ROOT"
stamp="$(date -u +%Y%m%dT%H%M%S)_$(date +%N)"
release="$RELEASE_ROOT/release-$stamp"
staging="$RELEASE_ROOT/.staging-$stamp"
temporary="$(mktemp -d /run/aichat-backend-deploy.XXXXXX)"
install -d -o root -g root -m 0755 "$staging"

trap 'handle_error "$?"' ERR
trap 'handle_error 130' INT TERM

git_read archive --format=tar "$commit:backend" \
  | tar --extract --directory "$staging" --no-same-owner --no-same-permissions

if find "$staging" -xdev \( -type l -o ! -type d -a ! -type f \) -print -quit | grep -q .; then
  echo 'ERROR: backend snapshot contains a symlink or special file' >&2
  false
fi
for forbidden in .env media .cache venv staticfiles; do
  if [[ -e "$staging/$forbidden" || -L "$staging/$forbidden" ]]; then
    echo "ERROR: backend snapshot contains forbidden runtime content: $forbidden" >&2
    false
  fi
done
while IFS= read -r -d '' path; do
  relative="${path#"$staging"/}"
  if [[ ! "$relative" =~ ^([A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$ ]]; then
    echo "ERROR: unsafe release path: $relative" >&2
    false
  fi
done < <(find "$staging" -xdev -mindepth 1 -print0)

file_count="$(find "$staging" -xdev -type f -printf . | wc -c)"
byte_count="$(du -sb -- "$staging" | cut -f1)"
if (( file_count < 1 || file_count > 5000 || byte_count > 134217728 )); then
  echo 'ERROR: backend snapshot exceeds the release file/byte bounds' >&2
  false
fi

chown -R root:root -- "$staging"
find "$staging" -xdev -type d -exec chmod 0755 -- {} +
find "$staging" -xdev -type f -exec chmod 0644 -- {} +
printf '%s\n' "$commit" > "$staging/.release-commit"
chmod 0644 "$staging/.release-commit"
(
  cd "$staging"
  find . -xdev -type f ! -name '.release-manifest.sha256' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > .release-manifest.sha256
)
chown root:root "$staging/.release-manifest.sha256"
chmod 0644 "$staging/.release-manifest.sha256"

if find "$staging" -xdev \( ! -user root -o ! -group root \) -print -quit | grep -q .; then
  echo 'ERROR: staged release ownership validation failed' >&2
  false
fi
if find "$staging" -xdev -type d ! -perm 0755 -print -quit | grep -q .; then
  echo 'ERROR: staged release directory mode validation failed' >&2
  false
fi
if find "$staging" -xdev -type f ! -perm 0644 -print -quit | grep -q .; then
  echo 'ERROR: staged release file mode validation failed' >&2
  false
fi
(
  cd "$staging"
  sha256sum --check --strict .release-manifest.sha256 >/dev/null
)

preflight=(
  runuser --user aichat -- env --chdir="$staging"
  AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1
  "$VENV_DIR/bin/python"
)
"${preflight[@]}" manage.py check --deploy
"${preflight[@]}" manage.py migrate --check
imported_from="$("${preflight[@]}" -c \
  'from pathlib import Path; import chat; print(Path(chat.__file__).resolve())')"
if [[ "$imported_from" != "$staging"/* ]]; then
  echo 'ERROR: preflight imported application code outside the staged release' >&2
  false
fi

mv -- "$staging" "$release"
staging=''
backup_units

next_link="$LIVE_PATH.next.$stamp"
ln -s -- "$release" "$next_link"
mv -Tf -- "$next_link" "$LIVE_PATH"
next_link=''
activation_started=1

install_committed_units
systemctl daemon-reload
systemctl restart "$SERVICE"
wait_for_release

trap - ERR INT TERM
rm -rf --one-file-system -- "$temporary"
temporary=''
"$RETENTION_TOOL" --apply --family backend --keep-inactive 2

echo "Backend release active: $release"
echo "Commit: $commit"
if [[ -n "$previous" ]]; then
  echo "Rollback target retained: $previous"
else
  echo 'Atomic backend release layout bootstrapped successfully'
fi
