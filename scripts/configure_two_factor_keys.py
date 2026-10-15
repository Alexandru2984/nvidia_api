#!/usr/bin/python3
"""Atomically bootstrap or extend a private application keyring in dotenv.

The command never prints key material or copies the rest of the environment to
stdout. Retired keys are intentionally retained; the Django audit command must
prove they are unused before an operator removes one manually.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import stat
import tempfile
from pathlib import Path

KEY_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
ASSIGNMENT_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=')
SCOPES = {
    'two-factor': (
        'TWO_FACTOR_KEYS',
        'TWO_FACTOR_ACTIVE_KEY_ID',
        'TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED',
    ),
    'admin-audit': (
        'ADMIN_AUDIT_KEYS',
        'ADMIN_AUDIT_ACTIVE_KEY_ID',
        'ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED',
    ),
}
MANAGED = tuple(name for names in SCOPES.values() for name in names)
MAX_ENV_BYTES = 1024 * 1024


class ConfigurationError(RuntimeError):
    pass


def _read_environment(path: Path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ConfigurationError('environment path must be a regular file')
    if info.st_size > MAX_ENV_BYTES:
        raise ConfigurationError('environment file is unexpectedly large')
    if stat.S_IMODE(info.st_mode) & 0o027:
        raise ConfigurationError('environment file has unsafe write/other permissions')
    if os.geteuid() != 0 and info.st_uid != os.geteuid():
        raise ConfigurationError('environment file must be owned by the current user')
    try:
        text = path.read_text(encoding='utf-8')
    except UnicodeError as exc:
        raise ConfigurationError('environment file is not valid UTF-8') from exc
    values = {}
    for line in text.splitlines():
        match = ASSIGNMENT_RE.match(line)
        if not match or match.group(1) not in MANAGED:
            continue
        name = match.group(1)
        if name in values:
            raise ConfigurationError(f'duplicate managed setting: {name}')
        values[name] = line.split('=', 1)[1].strip()
    return info, text, values


def _validated_keyring(raw: str):
    try:
        keyring = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ConfigurationError('existing keyring is not valid JSON') from exc
    if not isinstance(keyring, dict) or not 1 <= len(keyring) <= 8:
        raise ConfigurationError('existing keyring has an invalid size')
    for key_id, value in keyring.items():
        if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
            raise ConfigurationError('existing keyring has an invalid identifier')
        if not isinstance(value, str):
            raise ConfigurationError('existing keyring has invalid key material')
        try:
            decoded = base64.b64decode(value.encode('ascii'), altchars=b'-_', validate=True)
        except (UnicodeError, binascii.Error, ValueError) as exc:
            raise ConfigurationError('existing keyring has invalid key material') from exc
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode('ascii') != value:
            raise ConfigurationError('existing keyring has invalid key material')
    return keyring


def _replace_settings(text: str, replacements):
    remaining = dict(replacements)
    output = []
    for line in text.splitlines():
        match = ASSIGNMENT_RE.match(line)
        name = match.group(1) if match else None
        if name in remaining:
            output.append(f'{name}={remaining.pop(name)}')
        else:
            output.append(line)
    if output and output[-1]:
        output.append('')
    output.extend(f'{name}={remaining[name]}' for name in MANAGED if name in remaining)
    return '\n'.join(output) + '\n'


def _atomic_replace(path: Path, info, content: str):
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', dir=path.parent, prefix='.two-factor-env.',
            delete=False,
        ) as handle:
            temporary_name = handle.name
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            # Preserve both owner and group exactly. On deployments where the
            # interactive account is not a member of the service group, this
            # intentionally requires sudo instead of silently making .env
            # unreadable to the application identity.
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        temporary_name = None
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def configure(path: Path, key_id: str, *, rotate: bool, scope='two-factor'):
    if not KEY_ID_RE.fullmatch(key_id):
        raise ConfigurationError('key identifier must match [A-Za-z0-9_-]{1,32}')
    try:
        keys_name, active_name, legacy_name = SCOPES[scope]
    except KeyError as exc:
        raise ConfigurationError('unknown keyring scope') from exc
    info, text, values = _read_environment(path)
    present = set(values).intersection({keys_name, active_name, legacy_name})
    if rotate:
        if {keys_name, active_name} - present:
            raise ConfigurationError('rotation requires an existing keyring')
        keyring = _validated_keyring(values[keys_name])
        if key_id in keyring:
            raise ConfigurationError('new key identifier already exists')
        if len(keyring) >= 8:
            raise ConfigurationError('keyring is full; audit and retire an unused key first')
    else:
        if present:
            raise ConfigurationError('keyring settings already exist; use --rotate')
        keyring = {}

    keyring[key_id] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('ascii')
    replacements = {
        keys_name: json.dumps(keyring, separators=(',', ':'), sort_keys=True),
        active_name: key_id,
    }
    if legacy_name not in values:
        replacements[legacy_name] = 'false'
    _atomic_replace(path, info, _replace_settings(text, replacements))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--env-file', required=True, type=Path)
    parser.add_argument('--key-id', required=True)
    parser.add_argument('--scope', choices=sorted(SCOPES), default='two-factor')
    parser.add_argument('--rotate', action='store_true')
    args = parser.parse_args()
    try:
        configure(args.env_file, args.key_id, rotate=args.rotate, scope=args.scope)
    except (ConfigurationError, OSError) as exc:
        parser.error(str(exc))
    action = 'Rotated' if args.rotate else 'Bootstrapped'
    print(
        f'{action} the {args.scope} keyring; active_key_id={args.key_id}. '
        'No key material was printed.'
    )


if __name__ == '__main__':
    main()
