#!/usr/bin/python3
"""Fail closed when the application runtime contains dotenv secret copies."""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import re
import stat
from pathlib import Path

ALLOWED_DOTENV_NAMES = frozenset({'.env', '.env.example'})
DOTENV_COPY_RE = re.compile(r'(^|[._-])env($|[._-])', re.IGNORECASE)
MAX_DOTENV_BYTES = 64 * 1024


def _looks_like_dotenv_copy(name: str) -> bool:
    return name not in ALLOWED_DOTENV_NAMES and bool(DOTENV_COPY_RE.search(name))


def validate_runtime_secret_hygiene(
    runtime_dir: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> list[str]:
    """Return fixed, content-free failures for an unsafe runtime boundary."""
    failures: list[str] = []
    runtime_dir = Path(runtime_dir)
    try:
        runtime_info = runtime_dir.lstat()
        if not stat.S_ISDIR(runtime_info.st_mode) or runtime_dir.is_symlink():
            return ['runtime directory is missing or unsafe']

        dotenv = runtime_dir / '.env'
        dotenv_info = dotenv.lstat()
        if (
            not stat.S_ISREG(dotenv_info.st_mode)
            or dotenv.is_symlink()
            or dotenv_info.st_uid != expected_uid
            or dotenv_info.st_gid != expected_gid
            or stat.S_IMODE(dotenv_info.st_mode) != 0o640
            or not 1 <= dotenv_info.st_size <= MAX_DOTENV_BYTES
        ):
            failures.append('active dotenv ownership, mode or shape is unsafe')

        with os.scandir(runtime_dir) as entries:
            if any(_looks_like_dotenv_copy(entry.name) for entry in entries):
                failures.append('runtime directory contains a forbidden dotenv copy')
    except OSError:
        return ['runtime secret boundary could not be inspected safely']
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime-dir', default='/home/micu/nvidia/backend')
    parser.add_argument('--owner', default='micu')
    parser.add_argument('--group', default='aichat')
    args = parser.parse_args()
    try:
        expected_uid = pwd.getpwnam(args.owner).pw_uid
        expected_gid = grp.getgrnam(args.group).gr_gid
    except KeyError:
        print('ERROR: expected runtime identity is unavailable')
        return 2

    failures = validate_runtime_secret_hygiene(
        Path(args.runtime_dir),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if failures:
        for failure in failures:
            print(f'ERROR: {failure}')
        return 1
    print('Runtime secret hygiene is valid.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
