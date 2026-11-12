"""Bounded, content-free resolution for application secret settings."""

import os
import stat
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured


DEFAULT_MAX_SECRET_BYTES = 8 * 1024


def _invalid(name, reason):
    raise ImproperlyConfigured(f'{name} {reason}.')


def _validate_value(name, value, max_bytes):
    try:
        encoded = value.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise ImproperlyConfigured(f'{name} must be valid UTF-8.') from exc
    if not encoded:
        _invalid(name, 'must not be empty')
    if len(encoded) > max_bytes:
        _invalid(name, 'exceeds the safe size bound')
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        _invalid(name, 'contains a control character')
    return value


def _read_secret_file(name, raw_path, max_bytes):
    path = Path(raw_path)
    if not path.is_absolute() or '..' in path.parts:
        _invalid(name, 'file must be an absolute canonical path')
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            _invalid(name, 'file must be a regular nonsymlink file')
        if path.resolve(strict=True) != path:
            _invalid(name, 'file must be an absolute canonical path')
        if not 1 <= metadata.st_size <= max_bytes + 2:
            _invalid(name, 'file has an unsafe size')
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except ImproperlyConfigured:
        raise
    except (OSError, RuntimeError) as exc:
        raise ImproperlyConfigured(f'{name} file is unavailable.') from exc

    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            _invalid(name, 'file must be a regular nonsymlink file')
        if (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino):
            _invalid(name, 'file changed while it was opened')
        chunks = []
        bytes_read = 0
        while bytes_read <= max_bytes + 2:
            chunk = os.read(descriptor, max_bytes + 3 - bytes_read)
            if not chunk:
                break
            chunks.append(chunk)
            bytes_read += len(chunk)
        if bytes_read > max_bytes + 2:
            _invalid(name, 'file has an unsafe size')
        payload = b''.join(chunks)
    except OSError as exc:
        raise ImproperlyConfigured(f'{name} file is unavailable.') from exc
    finally:
        os.close(descriptor)

    if payload.endswith(b'\r\n'):
        payload = payload[:-2]
    elif payload.endswith(b'\n'):
        payload = payload[:-1]
    try:
        value = payload.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ImproperlyConfigured(f'{name} file must contain valid UTF-8.') from exc
    return _validate_value(name, value, max_bytes)


def secret_setting(name, *, required=True, default='', max_bytes=DEFAULT_MAX_SECRET_BYTES):
    """Resolve NAME or NAME_FILE, rejecting ambiguous and unsafe inputs."""
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= 64 * 1024:
        raise ValueError('max_bytes is outside the supported bound')
    file_name = f'{name}_FILE'
    has_value = name in os.environ
    has_file = file_name in os.environ
    if has_value and has_file:
        _invalid(name, f'and {file_name} must not both be set')
    if has_file:
        return _read_secret_file(name, os.environ[file_name], max_bytes)
    if has_value:
        return _validate_value(name, os.environ[name], max_bytes)
    if required:
        _invalid(name, f'or {file_name} must be set')
    return default
