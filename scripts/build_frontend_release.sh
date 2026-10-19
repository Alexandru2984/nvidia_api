#!/usr/bin/env bash
# Build committed frontend sources and bind the output to their Git identities.
set -euo pipefail
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
FRONTEND_DIR="$REPO_DIR/frontend"
DIST_DIR="$FRONTEND_DIR/dist"

if (( EUID == 0 )); then
  echo 'ERROR: build the frontend as the unprivileged deployment user' >&2
  exit 1
fi
for command in env git grep npm; do
  command -v "$command" >/dev/null || {
    echo "ERROR: required command is missing: $command" >&2
    exit 1
  }
done
if env | grep -q '^VITE_'; then
  echo 'ERROR: refusing ambient VITE_* values in a release build' >&2
  exit 1
fi

git_read() {
  git -C "$REPO_DIR" "$@"
}

if [[ -n "$(git_read status --porcelain=v1 --untracked-files=all -- frontend)" ]] \
  || ! git_read diff --quiet HEAD -- frontend; then
  echo 'ERROR: refusing to build frontend changes that are not committed' >&2
  exit 1
fi
unexpected_ignored="$(
  git_read ls-files --others --ignored --exclude-standard -- frontend \
    | grep -Ev '^frontend/(dist|node_modules|playwright-report|test-results|\.vite)/' \
    | head -n 1 || true
)"
if [[ -n "$unexpected_ignored" ]]; then
  echo 'ERROR: ignored frontend input exists outside approved build/test directories' >&2
  exit 1
fi

commit="$(git_read rev-parse --verify 'HEAD^{commit}')"
frontend_tree="$(git_read rev-parse --verify "$commit:frontend")"
env -u NODE_OPTIONS -u NODE_PATH npm --prefix "$FRONTEND_DIR" run build

[[ -d "$DIST_DIR" && ! -L "$DIST_DIR" ]] || {
  echo 'ERROR: frontend build did not create a safe dist directory' >&2
  exit 1
}
printf '%s\n' "$commit" > "$DIST_DIR/.release-commit"
printf '%s\n' "$frontend_tree" > "$DIST_DIR/.release-frontend-tree"
chmod 0644 "$DIST_DIR/.release-commit" "$DIST_DIR/.release-frontend-tree"

printf 'Frontend release build ready: commit=%s tree=%s\n' "$commit" "$frontend_tree"
