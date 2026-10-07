#!/usr/bin/env bash
# Stage a root-owned frontend release and atomically switch the nginx webroot.
set -euo pipefail
umask 022

DOMAIN='aichat.micutu.com'
REPO_DIR='/home/micu/nvidia'
DIST_DIR="$REPO_DIR/frontend/dist"
RELEASE_ROOT='/var/www/aichat-releases'
LIVE_PATH='/var/www/aichat.micutu.com'
BOOTSTRAP=0
previous=''
legacy=''
next_link=''

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
  echo 'ERROR: frontend activation failed; restoring the previous webroot' >&2
  if ! restore_previous_webroot; then
    echo 'CRITICAL: automatic frontend rollback failed; manual recovery is required' >&2
  fi
  exit "$status"
}

if [[ "${1:-}" == '--bootstrap' ]]; then
  BOOTSTRAP=1
  shift
fi
if (( $# != 0 )); then
  echo 'Usage: sudo scripts/deploy_frontend.sh [--bootstrap]' >&2
  exit 2
fi
if (( EUID != 0 )); then
  echo 'ERROR: frontend deployment must run as root' >&2
  exit 1
fi
if [[ ! -d "$DIST_DIR" || -L "$DIST_DIR" ]]; then
  echo 'ERROR: frontend/dist is missing or is a symlink; build as the deployment user first' >&2
  exit 1
fi
for required in index.html .well-known/security.txt assets; do
  if [[ ! -e "$DIST_DIR/$required" ]]; then
    echo "ERROR: frontend/dist/$required is missing" >&2
    exit 1
  fi
done
if find "$DIST_DIR" -xdev -type l -print -quit | grep -q .; then
  echo 'ERROR: frontend/dist must not contain symlinks' >&2
  exit 1
fi
if grep -Eiq "<script[^>]+src=[\"'][[:space:]]*https?://" "$DIST_DIR/index.html"; then
  echo 'ERROR: built index contains a cross-origin script' >&2
  exit 1
fi

install -d -o root -g root -m 0755 "$RELEASE_ROOT"
stamp="$(date -u +%Y%m%dT%H%M%S)_$(date +%N)"
release="$RELEASE_ROOT/release-$stamp"
install -d -o root -g root -m 0755 "$release"
rsync -a --delete --chown=root:root --chmod=D0755,F0644 -- "$DIST_DIR/" "$release/"

if find "$release" -xdev \( ! -user root -o ! -group root \) -print -quit | grep -q .; then
  echo 'ERROR: staged release ownership validation failed' >&2
  exit 1
fi
if find "$release" -xdev -type d ! -perm 0755 -print -quit | grep -q .; then
  echo 'ERROR: staged release directory mode validation failed' >&2
  exit 1
fi
if find "$release" -xdev -type f ! -perm 0644 -print -quit | grep -q .; then
  echo 'ERROR: staged release file mode validation failed' >&2
  exit 1
fi

trap 'handle_activation_error "$?"' ERR
trap 'handle_activation_error 130' INT TERM

if [[ -L "$LIVE_PATH" ]]; then
  if (( BOOTSTRAP )); then
    echo 'ERROR: --bootstrap is valid only for the legacy directory deployment' >&2
    exit 1
  fi
  previous="$(readlink -f -- "$LIVE_PATH")"
  if [[ "$previous" != "$RELEASE_ROOT"/* || ! -d "$previous" ]]; then
    echo 'ERROR: live symlink does not target the validated release root' >&2
    exit 1
  fi
elif [[ -d "$LIVE_PATH" && ! -L "$LIVE_PATH" ]]; then
  if (( ! BOOTSTRAP )); then
    echo 'ERROR: legacy directory detected; review it and rerun once with --bootstrap' >&2
    exit 1
  fi
  if mountpoint -q "$LIVE_PATH"; then
    echo 'ERROR: refusing to replace a mounted webroot' >&2
    exit 1
  fi
  legacy="$RELEASE_ROOT/legacy-$stamp"
  mv -- "$LIVE_PATH" "$legacy"
  previous="$legacy"
elif [[ -e "$LIVE_PATH" ]]; then
  echo 'ERROR: live path is neither a directory nor a symlink' >&2
  exit 1
elif (( ! BOOTSTRAP )); then
  echo 'ERROR: live path is missing; explicit --bootstrap is required' >&2
  exit 1
fi

next_link="$LIVE_PATH.next.$stamp"
ln -s -- "$release" "$next_link"
mv -Tf -- "$next_link" "$LIVE_PATH"

origin_curl=(curl --silent --show-error --resolve "$DOMAIN:443:127.0.0.1")
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

echo "Frontend release active: $release"
if [[ -n "$previous" ]]; then
  echo "Rollback target retained: $previous"
fi
