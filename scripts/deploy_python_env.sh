#!/usr/bin/env bash
# Build a minimal root-owned Python runtime from committed pinned requirements,
# switch it atomically, and roll back a live service if validation fails.
set -euo pipefail
umask 022

DOMAIN='aichat.micutu.com'
REPO_DIR='/home/micu/nvidia'
RUNTIME_DIR='/home/micu/nvidia/backend'
APP_LIVE='/opt/aichat-backend-current'
APP_RELEASE_ROOT='/opt/aichat-backend-releases'
RELEASE_ROOT='/opt/aichat-python-envs'
LIVE_PATH='/opt/aichat-python-current'
SERVICE='aichat-backend.service'
PYTHON='/usr/bin/python3.14'
BOOTSTRAP=0

previous=''
release=''
activation_started=0
service_uses_release=0
next_link=''

usage() {
  echo 'Usage: sudo scripts/deploy_python_env.sh [--bootstrap]' >&2
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
    "https://$DOMAIN/media/python-env-deploy-probe")" || return 1
  [[ "$media_code" == '404' ]] || return 1
  private_code="$(origin_curl --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/api/conversations/")" || return 1
  [[ "$private_code" == '403' ]] || return 1
}

wait_for_environment() {
  local attempt main_pid process_exe

  for ((attempt = 1; attempt <= 45; attempt++)); do
    if systemctl is-active --quiet "$SERVICE" && health_ready 2>/dev/null; then
      main_pid="$(systemctl show --property=MainPID --value "$SERVICE")"
      if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]]; then
        process_exe="$(readlink -f -- "/proc/$main_pid/exe")"
        if [[ "$process_exe" == "$release/bin/python" ]]; then
          full_probes
          return
        fi
      fi
    fi
    sleep 1
  done
  return 1
}

restore_previous_environment() {
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
    echo 'ERROR: Python environment activation failed; restoring the previous target' >&2
    restore_previous_environment || true
    if (( service_uses_release )); then
      systemctl restart "$SERVICE" || true
      if ! health_ready >/dev/null 2>&1; then
        echo 'CRITICAL: Python environment rollback did not restore backend health' >&2
      fi
    fi
  elif [[ -n "$release" && -d "$release" ]]; then
    rm -rf --one-file-system -- "$release"
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
  echo 'ERROR: Python environment deployment must run as root' >&2
  exit 1
fi
for command in git sha256sum runuser curl systemctl readlink "$PYTHON"; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
if [[ ! -d "$REPO_DIR/.git" || -L "$REPO_DIR/.git" ]]; then
  echo 'ERROR: repository metadata is missing or unsafe' >&2
  exit 1
fi
if [[ ! -L "$APP_LIVE" ]]; then
  echo 'ERROR: active backend application release is missing or unsafe' >&2
  exit 1
fi
app_release="$(readlink -f -- "$APP_LIVE")"
if [[ "$app_release" != "$APP_RELEASE_ROOT"/* || ! -d "$app_release" || -L "$app_release" ]]; then
  echo 'ERROR: active backend application symlink leaves the trusted release root' >&2
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
    echo 'ERROR: --bootstrap is valid only before the first immutable Python environment' >&2
    exit 1
  fi
  previous="$(readlink -f -- "$LIVE_PATH")"
  if [[ "$previous" != "$RELEASE_ROOT"/* || ! -d "$previous" || -L "$previous" ]]; then
    echo 'ERROR: live Python symlink does not target the trusted release root' >&2
    exit 1
  fi
elif [[ -e "$LIVE_PATH" ]]; then
  echo 'ERROR: live Python environment path is not a symlink' >&2
  exit 1
elif (( ! BOOTSTRAP )); then
  echo 'ERROR: first Python environment deployment requires explicit --bootstrap' >&2
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
installed_exec="$(systemctl show --property=ExecStart --value "$SERVICE")"
if [[ "$installed_exec" == *'/opt/aichat-python-current/bin/python'* ]]; then
  service_uses_release=1
elif (( ! BOOTSTRAP )); then
  echo 'ERROR: installed backend unit does not use the immutable Python environment' >&2
  exit 1
fi

install -d -o root -g root -m 0755 "$RELEASE_ROOT"
stamp="$(date -u +%Y%m%dT%H%M%S)_$(date +%N)"
release="$RELEASE_ROOT/release-$stamp"
install -d -o root -g root -m 0755 "$release"

trap 'handle_error "$?"' ERR
trap 'handle_error 130' INT TERM

"$PYTHON" -m venv --copies "$release"
git_read show "$commit:backend/requirements.txt" > "$release/.release-requirements.txt"
printf '%s\n' "$commit" > "$release/.release-commit"
chown -R nobody:nogroup -- "$release"

runuser --user nobody -- env \
  HOME=/nonexistent PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 \
  "$release/bin/python" -m pip install \
  --no-cache-dir --only-binary=:all: --requirement "$release/.release-requirements.txt"
runuser --user nobody -- env HOME=/nonexistent PYTHONDONTWRITEBYTECODE=1 \
  "$release/bin/python" -m pip check
runuser --user nobody -- env HOME=/nonexistent PYTHONDONTWRITEBYTECODE=1 \
  "$release/bin/python" - "$release/.release-requirements.txt" <<'PY'
from importlib.metadata import distributions
from pathlib import Path
import re
import sys

from packaging.utils import canonicalize_name

expected = {}
for number, raw in enumerate(Path(sys.argv[1]).read_text(encoding='utf-8').splitlines(), 1):
    line = raw.strip()
    if not line or line.startswith('#'):
        continue
    match = re.fullmatch(r'([A-Za-z0-9._-]+)==([^\s]+)', line)
    if not match:
        raise SystemExit(f'unsupported requirement at line {number}')
    name = canonicalize_name(match.group(1))
    if name in expected:
        raise SystemExit(f'duplicate requirement at line {number}')
    expected[name] = match.group(2)

installed = {
    canonicalize_name(dist.metadata['Name']): dist.version
    for dist in distributions()
    if dist.metadata.get('Name')
}
missing = sorted(set(expected) - set(installed))
wrong = sorted(name for name, version in expected.items() if installed.get(name) != version)
unexpected = sorted(set(installed) - set(expected) - {'pip'})
if missing or wrong or unexpected:
    raise SystemExit(
        f'package set mismatch: missing={missing}, wrong={wrong}, unexpected={unexpected}'
    )
print(f'validated {len(expected)} pinned runtime packages')
PY

preflight=(
  runuser --user aichat -- env --chdir="$APP_LIVE"
  AICHAT_RUNTIME_DIR="$RUNTIME_DIR" PYTHONDONTWRITEBYTECODE=1
  "$release/bin/python"
)
"${preflight[@]}" manage.py check --deploy
"${preflight[@]}" manage.py migrate --check
"${preflight[@]}" -c 'import django, gunicorn, psycopg2, cryptography, lxml; print("runtime imports ok")'

if [[ -L "$release/lib64" && "$(readlink -- "$release/lib64")" == 'lib' ]]; then
  unlink -- "$release/lib64"
fi
if find "$release" -xdev \( -type l -o ! -type d -a ! -type f \) -print -quit | grep -q .; then
  echo 'ERROR: Python environment contains a symlink or special file' >&2
  false
fi
while IFS= read -r -d '' path; do
  relative="${path#"$release"/}"
  if [[ ! "$relative" =~ ^([A-Za-z0-9._\[\]-]+/)*[A-Za-z0-9._\[\]-]+$ ]]; then
    echo "ERROR: unsafe Python environment path: $relative" >&2
    false
  fi
done < <(find "$release" -xdev -mindepth 1 -print0)

file_count="$(find "$release" -xdev -type f -printf . | wc -c)"
byte_count="$(du -sb -- "$release" | cut -f1)"
if (( file_count < 1 || file_count > 20000 || byte_count > 536870912 )); then
  echo 'ERROR: Python environment exceeds the release file/byte bounds' >&2
  false
fi

chown -R root:root -- "$release"
find "$release" -xdev -type d -exec chmod 0755 -- {} +
find "$release" -xdev -type f -exec chmod 0644 -- {} +
chmod 0755 "$release/bin/python"
(
  cd "$release"
  sha256sum .release-requirements.txt > .release-requirements.sha256
  find . -xdev -type f ! -name '.release-manifest.sha256' -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum > .release-manifest.sha256
)
chown root:root "$release/.release-requirements.sha256" "$release/.release-manifest.sha256"
chmod 0644 "$release/.release-requirements.sha256" "$release/.release-manifest.sha256"

if find "$release" -xdev \( ! -user root -o ! -group root \) -print -quit | grep -q .; then
  echo 'ERROR: Python environment ownership validation failed' >&2
  false
fi
if find "$release" -xdev -type d ! -perm 0755 -print -quit | grep -q .; then
  echo 'ERROR: Python environment directory mode validation failed' >&2
  false
fi
if find "$release" -xdev -type f ! -path "$release/bin/python" ! -perm 0644 -print -quit \
  | grep -q .; then
  echo 'ERROR: Python environment file mode validation failed' >&2
  false
fi
if [[ ! -f "$release/bin/python" || ! -x "$release/bin/python" ]]; then
  echo 'ERROR: Python environment interpreter is not executable' >&2
  false
fi
(
  cd "$release"
  sha256sum --check --strict .release-requirements.sha256 >/dev/null
  sha256sum --check --strict .release-manifest.sha256 >/dev/null
)
"${preflight[@]}" -m pip check
"${preflight[@]}" manage.py check --deploy
"${preflight[@]}" -c 'import django, gunicorn, psycopg2, cryptography, lxml; print("final runtime imports ok")'

next_link="$LIVE_PATH.next.$stamp"
ln -s -- "$release" "$next_link"
mv -Tf -- "$next_link" "$LIVE_PATH"
next_link=''
activation_started=1

if (( service_uses_release )); then
  systemctl restart "$SERVICE"
  wait_for_environment
fi

trap - ERR INT TERM
echo "Python environment active: $release"
echo "Requirements commit: $commit"
if [[ -n "$previous" ]]; then
  echo "Rollback target retained: $previous"
else
  echo 'Immutable Python environment layout bootstrapped successfully'
fi
