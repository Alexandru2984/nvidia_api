#!/usr/bin/env bash
# Restore the newest AI Chat Hub PostgreSQL dump into an isolated scratch
# database, verify the expected schema and migrations, then always remove it.
set -euo pipefail
umask 077

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"
PYTHON="$BACKEND_DIR/venv/bin/python"
ENV_FILE="$BACKEND_DIR/.env"
BACKUP_ROOT="${RESTORE_BACKUP_DIR:-/home/micu/backups/nvidia_db}"

[[ -d "$BACKUP_ROOT" && ! -L "$BACKUP_ROOT" ]] || {
  echo 'ERROR: backup directory is missing or is a symlink' >&2
  exit 1
}

exec 9>"$BACKUP_ROOT/.restore-drill.lock"
flock -n 9 || { echo 'ERROR: another restore drill is running' >&2; exit 1; }

mapfile -d '' -t DB_VALUES < <("$PYTHON" -c '
import sys
from dotenv import dotenv_values
values = dotenv_values(sys.argv[1])
for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "DB_PORT"):
    sys.stdout.write((values.get(key) or "") + "\0")
' "$ENV_FILE")
[[ "${#DB_VALUES[@]}" == 5 ]] || { echo 'ERROR: cannot read database settings' >&2; exit 1; }

DB_NAME="${DB_VALUES[0]}"
DB_USER="${DB_VALUES[1]}"
DB_PASSWORD="${DB_VALUES[2]}"
DB_HOST="${DB_VALUES[3]:-127.0.0.1}"
DB_PORT="${DB_VALUES[4]:-5432}"
[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'ERROR: unsafe database name' >&2; exit 1; }
[[ "$DB_USER" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'ERROR: unsafe database user' >&2; exit 1; }
[[ "$DB_PORT" =~ ^[0-9]{1,5}$ ]] || { echo 'ERROR: unsafe database port' >&2; exit 1; }
[[ "$DB_HOST" == '127.0.0.1' || "$DB_HOST" == 'localhost' ]] || {
  echo 'ERROR: this drill only creates scratch databases on the local PostgreSQL cluster' >&2
  exit 1
}

LATEST="$($PYTHON -c '
from pathlib import Path
import re
import sys

directory, database = Path(sys.argv[1]), sys.argv[2]
pattern = re.compile(re.escape(database) + r"_\d{8}_\d{6}(?:_\d+)?\.sql\.gz")
candidates = [p for p in directory.iterdir()
              if pattern.fullmatch(p.name) and p.is_file() and not p.is_symlink()]
if not candidates:
    raise SystemExit("ERROR: no valid database dump found")
print(max(candidates, key=lambda path: path.stat().st_mtime))
' "$BACKUP_ROOT" "$DB_NAME")"

MODE="$(stat -c '%a' "$LATEST")"
if (( (8#$MODE & 077) != 0 )); then
  echo "ERROR: dump permissions are too broad ($MODE)" >&2
  exit 1
fi
gzip -t -- "$LATEST"

SUFFIX="$($PYTHON -c 'import secrets; print(secrets.token_hex(4))')"
SCRATCH_DB="${DB_NAME:0:20}_restore_drill_$(date -u +%Y%m%d%H%M%S)_${SUFFIX}"
[[ "$SCRATCH_DB" =~ ^[A-Za-z_][A-Za-z0-9_]{1,62}$ ]] || {
  echo 'ERROR: generated unsafe scratch database name' >&2
  exit 1
}

CREATED=0
cleanup() {
  unset PGPASSWORD
  if [[ "$CREATED" == 1 ]]; then
    sudo -n -u postgres dropdb --if-exists --force --port="$DB_PORT" -- "$SCRATCH_DB" >/dev/null
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sudo -n -u postgres createdb --port="$DB_PORT" --owner="$DB_USER" -- "$SCRATCH_DB"
CREATED=1
export PGPASSWORD="$DB_PASSWORD"
gzip -cd -- "$LATEST" | psql \
  --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" \
  --dbname="$SCRATCH_DB" --no-psqlrc --set=ON_ERROR_STOP=1 --quiet >/dev/null

TABLES="$(psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" \
  --dbname="$SCRATCH_DB" --no-psqlrc --tuples-only --no-align \
  --command="SELECT to_regclass('public.django_migrations') IS NOT NULL,
                    to_regclass('public.auth_user') IS NOT NULL,
                    to_regclass('public.chat_conversation') IS NOT NULL,
                    to_regclass('public.chat_message') IS NOT NULL;")"
[[ "$TABLES" == 't|t|t|t' ]] || { echo 'ERROR: required tables are missing' >&2; exit 1; }

DB_NAME="$SCRATCH_DB" "$PYTHON" "$BACKEND_DIR/manage.py" migrate --check --noinput

COUNTS="$(psql --host="$DB_HOST" --port="$DB_PORT" --username="$DB_USER" \
  --dbname="$SCRATCH_DB" --no-psqlrc --tuples-only --no-align --field-separator='|' \
  --command='SELECT (SELECT count(*) FROM django_migrations),
                    (SELECT count(*) FROM auth_user),
                    (SELECT count(*) FROM chat_conversation),
                    (SELECT count(*) FROM chat_message);')"

echo "$(date -Is) restore drill ok: $(basename "$LATEST") counts(migrations|users|conversations|messages)=$COUNTS"
