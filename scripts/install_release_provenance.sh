#!/usr/bin/env bash
# Provision or rotate the root-only Ed25519 release-provenance signer.
set -euo pipefail
umask 077

KEY_ROOT='/etc/aichat-release-provenance'
PUBLIC_ROOT="$KEY_ROOT/public"
PRIVATE_KEY="$KEY_ROOT/private.pem"
REPO_DIR='/home/micu/nvidia'
SOURCE_TOOL="$REPO_DIR/scripts/release_provenance.py"
TARGET_TOOL='/usr/local/libexec/aichat-release-provenance'
LOCK_FILE='/run/aichat-release-operation.lock'
ROTATE=0
CHECK_ONLY=0
temporary=''
previous_private=''
private_replaced=0

usage() {
  echo 'Usage: sudo scripts/install_release_provenance.sh [--check|--rotate]' >&2
}

cleanup() {
  local status="$?"

  trap - EXIT HUP INT TERM
  if (( status != 0 && private_replaced )) \
    && [[ -n "$previous_private" && -f "$previous_private" ]]; then
    rollback_private="$KEY_ROOT/.private.pem.$$.rollback"
    install -o root -g root -m 0600 -- "$previous_private" "$rollback_private" \
      && mv -Tf -- "$rollback_private" "$PRIVATE_KEY" || true
  fi
  if [[ -n "$temporary" && -d "$temporary" ]]; then
    rm -rf --one-file-system -- "$temporary"
  fi
  exit "$status"
}

case "${1:-}" in
  '') ;;
  --check) CHECK_ONLY=1; shift ;;
  --rotate) ROTATE=1; shift ;;
  *) usage; exit 2 ;;
esac
(( $# == 0 )) || { usage; exit 2; }
if (( EUID != 0 )); then
  echo 'ERROR: release-provenance key installation must run as root' >&2
  exit 1
fi
for command in cmp cut flock git install mktemp mv openssl sha256sum stat; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
exec 9>"$LOCK_FILE"
flock -n 9 || { echo 'ERROR: another release operation is running' >&2; exit 1; }
chown root:root -- "$LOCK_FILE"
chmod 0644 -- "$LOCK_FILE"
[[ -x "$SOURCE_TOOL" && ! -L "$SOURCE_TOOL" ]] || {
  echo 'ERROR: release-provenance verifier source is missing or unsafe' >&2
  exit 1
}
if ! git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" diff --quiet -- \
  || ! git -c safe.directory="$REPO_DIR" -C "$REPO_DIR" diff --cached --quiet --; then
  echo 'ERROR: tracked repository changes must be committed before key installation' >&2
  exit 1
fi
if (( CHECK_ONLY )); then
  [[ -f "$TARGET_TOOL" && ! -L "$TARGET_TOOL" \
    && "$(stat -c '%U:%G:%a' -- "$TARGET_TOOL")" == 'root:root:755' ]] || {
    echo 'ERROR: installed release-provenance verifier is missing or unsafe' >&2
    exit 1
  }
  cmp --silent -- "$SOURCE_TOOL" "$TARGET_TOOL" || {
    echo 'ERROR: installed release-provenance verifier is stale' >&2
    exit 1
  }
else
  install -o root -g root -m 0755 -- "$SOURCE_TOOL" "$TARGET_TOOL"
  cmp --silent -- "$SOURCE_TOOL" "$TARGET_TOOL"
fi

if [[ -e "$KEY_ROOT" || -L "$KEY_ROOT" ]]; then
  [[ -d "$KEY_ROOT" && ! -L "$KEY_ROOT" \
    && "$(stat -c '%U:%G:%a' -- "$KEY_ROOT")" == 'root:root:755' ]] || {
    echo 'ERROR: release-provenance key directory is unsafe' >&2
    exit 1
  }
else
  (( ! CHECK_ONLY )) || {
    echo 'ERROR: release-provenance key directory is missing' >&2
    exit 1
  }
  install -d -o root -g root -m 0755 "$KEY_ROOT"
fi
if [[ -e "$PUBLIC_ROOT" || -L "$PUBLIC_ROOT" ]]; then
  [[ -d "$PUBLIC_ROOT" && ! -L "$PUBLIC_ROOT" \
    && "$(stat -c '%U:%G:%a' -- "$PUBLIC_ROOT")" == 'root:root:755' ]] || {
    echo 'ERROR: release-provenance public-key directory is unsafe' >&2
    exit 1
  }
else
  (( ! CHECK_ONLY )) || {
    echo 'ERROR: release-provenance public-key directory is missing' >&2
    exit 1
  }
  install -d -o root -g root -m 0755 "$PUBLIC_ROOT"
fi

temporary="$(mktemp -d /run/aichat-release-provenance.XXXXXX)"
trap cleanup EXIT HUP INT TERM

validate_pair() {
  local private="$1" public_der="$temporary/public.der" key_id public

  [[ -f "$private" && ! -L "$private" \
    && "$(stat -c '%U:%G:%a' -- "$private")" == 'root:root:600' \
    && "$(stat -c '%s' -- "$private")" -ge 64 \
    && "$(stat -c '%s' -- "$private")" -le 4096 ]] || {
    echo 'ERROR: active release-provenance private key is unsafe' >&2
    return 1
  }
  openssl pkey -in "$private" -pubout -outform DER -out "$public_der"
  key_id="$(sha256sum "$public_der" | cut -d' ' -f1)"
  [[ "$key_id" =~ ^[0-9a-f]{64}$ ]] || {
    echo 'ERROR: could not derive the release-provenance key ID' >&2
    return 1
  }
  public="$PUBLIC_ROOT/$key_id.pem"
  [[ -f "$public" && ! -L "$public" \
    && "$(stat -c '%U:%G:%a' -- "$public")" == 'root:root:644' \
    && "$(stat -c '%s' -- "$public")" -ge 64 \
    && "$(stat -c '%s' -- "$public")" -le 4096 ]] || {
    echo 'ERROR: active release-provenance public key is missing or unsafe' >&2
    return 1
  }
  openssl pkey -pubin -in "$public" -outform DER -out "$temporary/retained.der"
  cmp --silent -- "$public_der" "$temporary/retained.der" || {
    echo 'ERROR: active and retained release-provenance keys differ' >&2
    return 1
  }
  printf '%s\n' "$key_id"
}

if (( CHECK_ONLY )); then
  key_id="$(validate_pair "$PRIVATE_KEY")"
  echo "Release-provenance signing boundary is valid: $key_id"
  exit 0
fi

if [[ -e "$PRIVATE_KEY" || -L "$PRIVATE_KEY" ]]; then
  [[ -f "$PRIVATE_KEY" && ! -L "$PRIVATE_KEY" ]] || {
    echo 'ERROR: active release-provenance private key path is unsafe' >&2
    exit 1
  }
  current_key_id="$(validate_pair "$PRIVATE_KEY")"
  if (( ! ROTATE )); then
    echo "Release-provenance signing boundary already exists: $current_key_id"
    exit 0
  fi
  previous_private="$temporary/previous-private.pem"
  install -o root -g root -m 0600 -- "$PRIVATE_KEY" "$previous_private"
elif (( ROTATE )); then
  echo 'ERROR: --rotate requires an existing validated signer' >&2
  exit 1
fi

new_private="$temporary/private.pem"
new_public="$temporary/public.pem"
new_public_der="$temporary/new-public.der"
openssl genpkey -algorithm ED25519 -out "$new_private"
chmod 0600 "$new_private"
chown root:root "$new_private"
openssl pkey -in "$new_private" -pubout -out "$new_public"
openssl pkey -in "$new_private" -pubout -outform DER -out "$new_public_der"
key_id="$(sha256sum "$new_public_der" | cut -d' ' -f1)"
[[ "$key_id" =~ ^[0-9a-f]{64}$ ]] || {
  echo 'ERROR: generated release-provenance key ID is invalid' >&2
  exit 1
}
retained_public="$PUBLIC_ROOT/$key_id.pem"
if [[ -e "$retained_public" || -L "$retained_public" ]]; then
  [[ -f "$retained_public" && ! -L "$retained_public" ]] || {
    echo 'ERROR: generated key collides with an unsafe retained public path' >&2
    exit 1
  }
  openssl pkey -pubin -in "$retained_public" -outform DER -out "$temporary/existing.der"
  cmp --silent -- "$new_public_der" "$temporary/existing.der" || {
    echo 'ERROR: generated key ID collides with different public material' >&2
    exit 1
  }
else
  install -o root -g root -m 0644 -- "$new_public" "$retained_public"
fi

staged_private="$KEY_ROOT/.private.pem.$$.new"
install -o root -g root -m 0600 -- "$new_private" "$staged_private"
mv -Tf -- "$staged_private" "$PRIVATE_KEY"
private_replaced=1
validated_id="$(validate_pair "$PRIVATE_KEY")"
[[ "$validated_id" == "$key_id" ]] || {
  echo 'ERROR: installed release-provenance signer changed unexpectedly' >&2
  exit 1
}
private_replaced=0
echo "Release-provenance signer active: $key_id"
