#!/usr/bin/env bash
# Exercise the complete backend suite in a disposable private PostgreSQL cluster.
set -euo pipefail
umask 077

if (( EUID == 0 )); then
  echo 'ERROR: run disposable PostgreSQL tests as an unprivileged user' >&2
  exit 1
fi
REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
TEST_PYTHON="$(command -v "${AICHAT_TEST_PYTHON:-$REPO_DIR/backend/venv/bin/python}")"
if [[ "$TEST_PYTHON" != /* ]]; then
  TEST_PYTHON="$PWD/$TEST_PYTHON"
fi
PG_BIN="$(pg_config --bindir)"
[[ -x "$TEST_PYTHON" && -x "$PG_BIN/initdb" && -x "$PG_BIN/pg_ctl" ]] || {
  echo 'ERROR: the backend test environment and local PostgreSQL tools are required' >&2
  exit 1
}
TEST_CLUSTER="$(mktemp -d /tmp/aichat-security-pg.XXXXXX)"
started=0

cleanup() {
  local result=$?
  trap - EXIT INT TERM
  if (( started )); then
    if "$PG_BIN/pg_ctl" -D "$TEST_CLUSTER/data" status >/dev/null; then
      if ! "$PG_BIN/pg_ctl" -D "$TEST_CLUSTER/data" -m fast -w stop >/dev/null; then
        echo "ERROR: PostgreSQL did not stop; retained temporary cluster: $TEST_CLUSTER" >&2
        exit 1
      fi
    elif [[ $? != 3 ]]; then
      echo "ERROR: PostgreSQL did not stop; retained temporary cluster: $TEST_CLUSTER" >&2
      exit 1
    fi
  fi
  [[ "$TEST_CLUSTER" == /tmp/aichat-security-pg.* && -d "$TEST_CLUSTER" && ! -L "$TEST_CLUSTER" ]] || exit 1
  rm -rf -- "$TEST_CLUSTER"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$PG_BIN/initdb" -D "$TEST_CLUSTER/data" -U aichat_test \
  --auth-local=trust --auth-host=reject --no-locale --encoding=UTF8 >/dev/null
# No TCP listener, no production config, and only the owner can reach the socket.
started=1
"$PG_BIN/pg_ctl" -D "$TEST_CLUSTER/data" -l "$TEST_CLUSTER/postgres.log" \
  -o "-k $TEST_CLUSTER -h '' -p 5432 -c shared_buffers=16MB -c max_connections=20" \
  -w start >/dev/null
"$PG_BIN/createdb" --host="$TEST_CLUSTER" --port=5432 --username=aichat_test aichat_security

cd -- "$REPO_DIR/backend"
"$TEST_PYTHON" - "$TEST_CLUSTER" <<'PY'
import sys
import types

import nvidia_chat.test_settings as base

test_settings = types.ModuleType('nvidia_chat._isolated_postgres_tests')
test_settings.__dict__.update({key: value for key, value in vars(base).items() if key.isupper()})
test_settings.DATABASES = {'default': {
    'ENGINE': 'django.db.backends.postgresql',
    'NAME': 'aichat_security',
    'USER': 'aichat_test',
    'HOST': sys.argv[1],
    'PORT': '5432',
}}
sys.modules[test_settings.__name__] = test_settings

import pytest

raise SystemExit(pytest.main([
    '--ds=' + test_settings.__name__, '-q', '--show-capture=no',
    'chat/tests',
]))
PY
