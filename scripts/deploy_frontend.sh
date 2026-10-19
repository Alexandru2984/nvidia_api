#!/usr/bin/env bash
# Stage a root-owned frontend release and atomically switch the nginx webroot.
set -euo pipefail
umask 022

DOMAIN='aichat.micutu.com'
REPO_DIR='/home/micu/nvidia'
DIST_DIR="$REPO_DIR/frontend/dist"
RELEASE_ROOT='/var/www/aichat-releases'
LIVE_PATH='/var/www/aichat.micutu.com'
RETENTION_TOOL="$REPO_DIR/scripts/archive_release_retention.py"
PROVENANCE_TOOL="$REPO_DIR/scripts/release_provenance.py"
LOCK_FILE='/run/aichat-release-operation.lock'
MAX_RELEASE_FILES=5000
MAX_RELEASE_BYTES=$((256 * 1024 * 1024))
BOOTSTRAP=0
PREFLIGHT_ONLY=0
previous=''
legacy=''
next_link=''
release=''
activation_started=0

usage() {
  echo 'Usage: sudo scripts/deploy_frontend.sh [--bootstrap|--preflight-only]' >&2
}

git_read() {
  git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" "$@"
}

validate_dist() {
  local commit expected_commit expected_tree file_count frontend_tree total_bytes
  local unexpected_ignored

  [[ -d "$DIST_DIR" && ! -L "$DIST_DIR" ]] || {
    echo 'ERROR: frontend/dist is missing or is a symlink; use scripts/build_frontend_release.sh first' >&2
    return 1
  }
  [[ -f "$DIST_DIR/index.html" && ! -L "$DIST_DIR/index.html" \
    && -f "$DIST_DIR/.well-known/security.txt" && ! -L "$DIST_DIR/.well-known/security.txt" \
    && -d "$DIST_DIR/assets" && ! -L "$DIST_DIR/assets" ]] || {
    echo 'ERROR: frontend/dist is missing a required regular file or assets directory' >&2
    return 1
  }
  if find "$DIST_DIR" -xdev ! -type d ! -type f -print -quit | grep -q .; then
    echo 'ERROR: frontend/dist contains a symlink or special file' >&2
    return 1
  fi
  read -r file_count total_bytes < <(
    find "$DIST_DIR" -xdev -type f -printf '%s\n' \
      | awk '{ files += 1; bytes += $1 } END { print files + 0, bytes + 0 }'
  )
  if (( file_count < 1 || file_count > MAX_RELEASE_FILES \
        || total_bytes < 1 || total_bytes > MAX_RELEASE_BYTES )); then
    echo 'ERROR: frontend/dist exceeds the release file-count or byte bound' >&2
    return 1
  fi
  for marker in .release-commit .release-frontend-tree; do
    [[ -f "$DIST_DIR/$marker" && ! -L "$DIST_DIR/$marker" \
      && "$(stat -c '%s' -- "$DIST_DIR/$marker")" -ge 2 \
      && "$(stat -c '%s' -- "$DIST_DIR/$marker")" -le 129 ]] || {
      echo "ERROR: frontend/dist/$marker is missing or malformed" >&2
      return 1
    }
  done
  commit="$(<"$DIST_DIR/.release-commit")"
  frontend_tree="$(<"$DIST_DIR/.release-frontend-tree")"
  expected_commit="$(git_read rev-parse --verify 'HEAD^{commit}')"
  expected_tree="$(git_read rev-parse --verify "$expected_commit:frontend")"
  [[ "$commit" == "$expected_commit" && "$frontend_tree" == "$expected_tree" \
    && "$commit" =~ ^[0-9a-f]{40,64}$ && "$frontend_tree" =~ ^[0-9a-f]{40,64}$ ]] || {
    echo 'ERROR: frontend build provenance does not match committed HEAD' >&2
    return 1
  }
  if [[ -n "$(git_read status --porcelain=v1 --untracked-files=all -- frontend)" ]] \
    || ! git_read diff --quiet HEAD -- frontend; then
    echo 'ERROR: refusing to deploy uncommitted frontend changes' >&2
    return 1
  fi
  unexpected_ignored="$(
    git_read ls-files --others --ignored --exclude-standard -- frontend \
      | grep -Ev '^frontend/(dist|node_modules|playwright-report|test-results|\.vite)/' \
      | head -n 1 || true
  )"
  if [[ -n "$unexpected_ignored" ]]; then
    echo 'ERROR: ignored frontend input exists outside approved build/test directories' >&2
    return 1
  fi
  if grep -Eiq "<script[^>]+src=[\"'][[:space:]]*https?://" "$DIST_DIR/index.html"; then
    echo 'ERROR: built index contains a cross-origin script' >&2
    return 1
  fi
}

validate_release_tree() {
  local file_count release="$1" require_provenance="${2:-1}" total_bytes

  [[ "$release" == "$RELEASE_ROOT"/release-* && -d "$release" && ! -L "$release" \
    && "$(stat -c '%U:%G:%a' -- "$release")" == 'root:root:755' ]] || {
    echo "ERROR: unsafe frontend release root: $release" >&2
    return 1
  }
  if find "$release" -xdev ! -type d ! -type f -print -quit | grep -q .; then
    echo "ERROR: frontend release contains a symlink or special file: $release" >&2
    return 1
  fi
  if find "$release" -xdev \( ! -user root -o ! -group root \) -print -quit | grep -q .; then
    echo "ERROR: frontend release ownership validation failed: $release" >&2
    return 1
  fi
  if find "$release" -xdev -type d ! -perm 0755 -print -quit | grep -q .; then
    echo "ERROR: frontend release directory mode validation failed: $release" >&2
    return 1
  fi
  if find "$release" -xdev -type f ! -perm 0644 -print -quit | grep -q .; then
    echo "ERROR: frontend release file mode validation failed: $release" >&2
    return 1
  fi
  read -r file_count total_bytes < <(
    find "$release" -xdev -type f -printf '%s\n' \
      | awk '{ files += 1; bytes += $1 } END { print files + 0, bytes + 0 }'
  )
  if (( file_count < 1 || file_count > MAX_RELEASE_FILES \
        || total_bytes < 1 || total_bytes > MAX_RELEASE_BYTES )); then
    echo "ERROR: frontend release exceeds the file-count or byte bound: $release" >&2
    return 1
  fi
  [[ -f "$release/.release-manifest.sha256" \
    && ! -L "$release/.release-manifest.sha256" ]] || {
    echo "ERROR: frontend release manifest is missing: $release" >&2
    return 1
  }
  (cd "$release" && sha256sum --quiet -c .release-manifest.sha256) || {
    echo "ERROR: frontend release manifest validation failed: $release" >&2
    return 1
  }
  if [[ -e "$release/.release-manifest.ed25519" \
    || -L "$release/.release-manifest.ed25519" \
    || -e "$release/.release-signing-key-id" \
    || -L "$release/.release-signing-key-id" ]]; then
    "$PROVENANCE_TOOL" verify --family frontend --release "$release" || {
      echo "ERROR: frontend release provenance validation failed: $release" >&2
      return 1
    }
  elif (( require_provenance )); then
    echo "ERROR: frontend release has no signed provenance: $release" >&2
    return 1
  else
    echo "NOTICE: transitional frontend release predates signed provenance: $release" >&2
  fi
}

restore_previous_webroot() {
  local rollback_link

  if [[ -n "$next_link" && -L "$next_link" ]]; then
    unlink -- "$next_link"
  fi

  if [[ -n "$legacy" ]]; then
    if [[ -L "$LIVE_PATH" ]]; then
      unlink -- "$LIVE_PATH"
    elif [[ -e "$LIVE_PATH" ]]; then
      echo 'CRITICAL: rollback refused because the live path is no longer a symlink' >&2
      return 1
    fi
    if [[ -d "$legacy" && ! -e "$LIVE_PATH" ]]; then
      mv -- "$legacy" "$LIVE_PATH"
    fi
  elif [[ -n "$previous" ]]; then
    if [[ -e "$LIVE_PATH" && ! -L "$LIVE_PATH" ]]; then
      echo 'CRITICAL: rollback refused because the live path is no longer a symlink' >&2
      return 1
    fi
    rollback_link="$LIVE_PATH.rollback.$stamp"
    ln -s -- "$previous" "$rollback_link"
    mv -Tf -- "$rollback_link" "$LIVE_PATH"
  elif [[ -L "$LIVE_PATH" ]]; then
    unlink -- "$LIVE_PATH"
  fi
}

handle_activation_error() {
  local status="${1:-1}"

  trap - ERR INT TERM
  if (( activation_started )); then
    echo 'ERROR: frontend activation failed; restoring the previous webroot' >&2
    if ! restore_previous_webroot; then
      echo 'CRITICAL: automatic frontend rollback failed; manual recovery is required' >&2
    fi
  elif [[ -n "$release" && -d "$release" ]]; then
    rm -rf --one-file-system -- "$release"
  fi
  exit "$status"
}

case "${1:-}" in
  --bootstrap) BOOTSTRAP=1; shift ;;
  --preflight-only) PREFLIGHT_ONLY=1; shift ;;
esac
if (( $# != 0 )); then
  usage
  exit 2
fi
if (( EUID != 0 )); then
  echo 'ERROR: frontend deployment must run as root' >&2
  exit 1
fi
for command in awk chmod chown curl date find flock git grep install ln mountpoint mv \
  readlink rsync sha256sum sort stat unlink xargs; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
for tool in "$RETENTION_TOOL" "$PROVENANCE_TOOL"; do
  [[ -x "$tool" && ! -L "$tool" ]] || {
    echo "ERROR: required release tool is missing or unsafe: $tool" >&2
    exit 1
  }
done

exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'ERROR: another release operation is running' >&2; exit 1; }

validate_dist

if [[ -e "$RELEASE_ROOT" || -L "$RELEASE_ROOT" ]]; then
  [[ -d "$RELEASE_ROOT" && ! -L "$RELEASE_ROOT" \
    && "$(stat -c '%U:%G:%a' -- "$RELEASE_ROOT")" == 'root:root:755' ]] || {
    echo 'ERROR: frontend release root is linked or has unsafe ownership/mode' >&2
    exit 1
  }
else
  install -d -o root -g root -m 0755 "$RELEASE_ROOT"
fi

if [[ -L "$LIVE_PATH" ]]; then
  if (( BOOTSTRAP )); then
    echo 'ERROR: --bootstrap is valid only for the legacy directory deployment' >&2
    exit 1
  fi
  previous="$(readlink -f -- "$LIVE_PATH")"
  if [[ "$(readlink -- "$LIVE_PATH")" != "$previous" ]]; then
    echo 'ERROR: live frontend symlink must directly name its release target' >&2
    exit 1
  fi
  validate_release_tree "$previous" 0
elif [[ -d "$LIVE_PATH" && ! -L "$LIVE_PATH" ]]; then
  if (( ! BOOTSTRAP )); then
    echo 'ERROR: legacy directory detected; review it and rerun once with --bootstrap' >&2
    exit 1
  fi
  if mountpoint -q "$LIVE_PATH"; then
    echo 'ERROR: refusing to replace a mounted webroot' >&2
    exit 1
  fi
elif [[ -e "$LIVE_PATH" || -L "$LIVE_PATH" ]]; then
  echo 'ERROR: live path is neither a directory nor a trusted symlink' >&2
  exit 1
elif (( ! BOOTSTRAP )); then
  echo 'ERROR: live path is missing; explicit --bootstrap is required' >&2
  exit 1
fi

if (( PREFLIGHT_ONLY )); then
  echo 'Frontend deployment preflight passed'
  exit 0
fi

stamp="$(date -u +%Y%m%dT%H%M%S)_$(date +%N)"
release="$RELEASE_ROOT/release-$stamp"
trap 'handle_activation_error "$?"' ERR
trap 'handle_activation_error 130' INT TERM
install -d -o root -g root -m 0755 "$release"
rsync -a --delete --chown=root:root --chmod=D0755,F0644 -- "$DIST_DIR/" "$release/"
"$PROVENANCE_TOOL" sign --family frontend --release "$release"

validate_release_tree "$release" 1

if [[ -d "$LIVE_PATH" && ! -L "$LIVE_PATH" ]]; then
  legacy="$RELEASE_ROOT/legacy-$stamp"
  mv -- "$LIVE_PATH" "$legacy"
  previous="$legacy"
fi

next_link="$LIVE_PATH.next.$stamp"
activation_started=1
ln -s -- "$release" "$next_link"
mv -Tf -- "$next_link" "$LIVE_PATH"

origin_curl=(curl --silent --show-error --connect-timeout 3 --max-time 10 \
  --resolve "$DOMAIN:443:127.0.0.1")
healthy=1
html="$("${origin_curl[@]}" --fail "https://$DOMAIN/" 2>/dev/null)" || healthy=0
if (( healthy )) && grep -Eiq "<script[^>]+src=[\"'][[:space:]]*https?://" <<<"$html"; then
  healthy=0
fi
if (( healthy )); then
  "${origin_curl[@]}" --fail --output /dev/null "https://$DOMAIN/api/health/" || healthy=0
fi
if (( healthy )); then
  media_code="$("${origin_curl[@]}" --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/media/deploy-probe" 2>/dev/null)" || healthy=0
  [[ "$media_code" == '404' ]] || healthy=0
fi
if (( healthy )); then
  private_code="$("${origin_curl[@]}" --output /dev/null --write-out '%{http_code}' \
    "https://$DOMAIN/api/conversations/" 2>/dev/null)" || healthy=0
  [[ "$private_code" == '403' ]] || healthy=0
fi

if (( ! healthy )); then
  echo 'ERROR: post-switch probes failed; restoring the previous webroot' >&2
  if ! restore_previous_webroot; then
    echo 'CRITICAL: automatic frontend rollback failed; manual recovery is required' >&2
  fi
  exit 1
fi

trap - ERR INT TERM
"$RETENTION_TOOL" --apply --family frontend --keep-inactive 2

echo "Frontend release active: $release"
if [[ -n "$previous" ]]; then
  echo "Rollback target retained: $previous"
fi
