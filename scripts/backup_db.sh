#!/usr/bin/env bash
# Daily PostgreSQL backup for AI Chat Hub. Reads credentials from
# backend/.env, writes gzipped dumps, keeps the newest $KEEP.
#
# Cron (daily at 02:30):
#   30 2 * * * /home/micu/nvidia/scripts/backup_db.sh >> /home/micu/backups/nvidia_db/backup.log 2>&1
set -euo pipefail
umask 077

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"
ENV_FILE="$BACKEND_DIR/.env"
OUT_DIR="${BACKUP_DIR:-$HOME/backups/nvidia_db}"
KEEP="${KEEP:-7}"
[[ "$KEEP" =~ ^[1-9][0-9]{0,2}$ ]] || { echo 'ERROR: KEEP must be 1..999' >&2; exit 1; }

# Parse dotenv exactly as the application does; never source/eval the env file.
mapfile -d '' -t DB_VALUES < <("$BACKEND_DIR/venv/bin/python" -c '
import sys
from dotenv import dotenv_values
values = dotenv_values(sys.argv[1])
for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "DB_PORT"):
    sys.stdout.write((values.get(key) or "") + "\0")
' "$ENV_FILE")
[[ "${#DB_VALUES[@]}" == 5 ]] || { echo 'ERROR: Cannot read database settings' >&2; exit 1; }
DB_NAME="${DB_VALUES[0]}"
DB_USER="${DB_VALUES[1]}"
DB_PASSWORD="${DB_VALUES[2]}"
DB_HOST="${DB_VALUES[3]:-127.0.0.1}"
DB_PORT="${DB_VALUES[4]:-5432}"

if [[ -z "$DB_NAME" || -z "$DB_USER" ]]; then
  echo "ERROR: DB_NAME/DB_USER missing from $ENV_FILE" >&2
  exit 1
fi
[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { echo 'ERROR: Unsafe database name' >&2; exit 1; }

mkdir -p "$OUT_DIR"
[[ ! -L "$OUT_DIR" ]] || { echo 'ERROR: Backup directory must not be a symlink' >&2; exit 1; }
chmod 700 "$OUT_DIR"
exec 9>"$OUT_DIR/.backup.lock"
flock -n 9 || { echo 'ERROR: Another backup is running' >&2; exit 1; }
STAMP="$(date +%Y%m%d_%H%M%S_%N)"
FILE="$OUT_DIR/${DB_NAME}_${STAMP}.sql.gz"
PARTIAL="$(mktemp "$OUT_DIR/.dump.XXXXXX")"
trap 'unlink -- "$PARTIAL" 2>/dev/null || true' EXIT

PGPASSWORD="$DB_PASSWORD" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "$PARTIAL"
gzip -t "$PARTIAL"
mv -- "$PARTIAL" "$FILE"

# Retention: keep the newest $KEEP dumps.
# Only exact dump names in this directory qualify; paths are passed as arguments.
"$BACKEND_DIR/venv/bin/python" -c '
from pathlib import Path
import re
import sys
directory, name, keep = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
pattern = re.compile(re.escape(name) + r"_\d{8}_\d{6}(?:_\d+)?\.sql\.gz")
dumps = sorted((p for p in directory.iterdir() if pattern.fullmatch(p.name)
    and p.is_file() and not p.is_symlink()), key=lambda p: p.stat().st_mtime, reverse=True)
for dump in dumps:
    dump.chmod(0o600)
for dump in dumps[keep:]:
    dump.unlink()
' "$OUT_DIR" "$DB_NAME" "$KEEP"

echo "$(date -Is) backup ok: $FILE ($(du -h "$FILE" | cut -f1))"
