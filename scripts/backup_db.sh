#!/usr/bin/env bash
# Daily PostgreSQL backup for AI Chat Hub. Reads credentials from
# backend/.env, writes gzipped dumps, keeps the newest $KEEP.
#
# Cron (daily at 02:30):
#   30 2 * * * /home/micu/nvidia/scripts/backup_db.sh >> /home/micu/backups/nvidia_db/backup.log 2>&1
set -euo pipefail

BACKEND_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../backend" && pwd)"
ENV_FILE="$BACKEND_DIR/.env"
OUT_DIR="${BACKUP_DIR:-$HOME/backups/nvidia_db}"
KEEP="${KEEP:-7}"

get() { grep -oP "^$1=\K.*" "$ENV_FILE" | tr -d '"' || true; }

DB_NAME="$(get DB_NAME)"
DB_USER="$(get DB_USER)"
DB_PASSWORD="$(get DB_PASSWORD)"
DB_HOST="$(get DB_HOST)"; DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="$(get DB_PORT)"; DB_PORT="${DB_PORT:-5432}"

if [[ -z "$DB_NAME" || -z "$DB_USER" ]]; then
  echo "ERROR: DB_NAME/DB_USER missing from $ENV_FILE" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
FILE="$OUT_DIR/${DB_NAME}_${STAMP}.sql.gz"

PGPASSWORD="$DB_PASSWORD" pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" | gzip > "$FILE"

# Retention: keep the newest $KEEP dumps.
ls -1t "$OUT_DIR/${DB_NAME}"_*.sql.gz | tail -n +$((KEEP + 1)) | xargs -r rm --

echo "$(date -Is) backup ok: $FILE ($(du -h "$FILE" | cut -f1))"
