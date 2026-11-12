#!/usr/bin/env python3
"""Emit bounded database configuration as NUL fields for trusted shell callers."""

import os
import re
import stat
import sys
from pathlib import Path

from dotenv import dotenv_values


NAME_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def fail(message):
    raise ValueError(message)


def validate_password(password):
    if not isinstance(password, str):
        fail('database credential is unavailable')
    try:
        encoded = password.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ValueError('database credential is not UTF-8') from exc
    if not 1 <= len(encoded) <= 4096:
        fail('database credential has an unsafe size')
    if any(ord(character) < 32 or ord(character) == 127 for character in password):
        fail('database credential is empty or malformed')
    return password


def read_password(path_value):
    path = Path(path_value)
    if not path.is_absolute() or '..' in path.parts:
        fail('database credential path is unsafe')
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or path.resolve(strict=True) != path
            or not 1 <= metadata.st_size <= 4098
        ):
            fail('database credential file is unsafe')
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError('database credential file is unavailable') from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
        ):
            fail('database credential file changed while opening')
        chunks = []
        bytes_read = 0
        while bytes_read <= 4098:
            chunk = os.read(descriptor, 4099 - bytes_read)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
        if bytes_read > 4098:
            fail('database credential file is oversized')
        payload = b''.join(chunks)
    finally:
        os.close(descriptor)
    if payload.endswith(b'\r\n'):
        payload = payload[:-2]
    elif payload.endswith(b'\n'):
        payload = payload[:-1]
    try:
        password = payload.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError('database credential file is not UTF-8') from exc
    return validate_password(password)


def database_values(env_file):
    try:
        metadata = env_file.lstat()
    except OSError as exc:
        raise ValueError('runtime configuration is unavailable') from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or env_file.is_symlink()
        or env_file.resolve(strict=True) != env_file
        or not 1 <= metadata.st_size <= 64 * 1024
    ):
        fail('runtime configuration is unsafe')
    values = dotenv_values(env_file, interpolate=False)
    direct = values.get('DB_PASSWORD')
    dotenv_file = values.get('DB_PASSWORD_FILE')
    process_file = os.environ.get('DB_PASSWORD_FILE')
    if dotenv_file and process_file and dotenv_file != process_file:
        fail('database credential file sources are ambiguous')
    file_value = process_file or dotenv_file
    if direct and file_value:
        fail('database credential sources are ambiguous')
    password = validate_password(direct) if direct else (
        read_password(file_value) if file_value else None
    )
    if password is None:
        fail('database credential is unavailable')
    result = [
        values.get('DB_NAME') or '',
        values.get('DB_USER') or '',
        password,
        values.get('DB_HOST') or '127.0.0.1',
        values.get('DB_PORT') or '5432',
    ]
    if not NAME_RE.fullmatch(result[0]) or not NAME_RE.fullmatch(result[1]):
        fail('database name or user is unsafe')
    if result[3] not in {'127.0.0.1', 'localhost'}:
        fail('database host is not local')
    if not result[4].isdigit() or not 1 <= int(result[4]) <= 65535:
        fail('database port is unsafe')
    return result


def main():
    if len(sys.argv) != 2:
        print('Usage: read_database_config.py ENV_FILE', file=sys.stderr)
        return 2
    try:
        fields = database_values(Path(sys.argv[1]))
    except (OSError, ValueError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    for field in fields:
        sys.stdout.write(field + '\0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
