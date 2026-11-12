#!/usr/bin/env python3
"""Stage or validate AI Chat Hub file-backed application credentials."""

import argparse
import grp
import os
import pwd
import re
import stat
import sys
from pathlib import Path

from dotenv import dotenv_values


MAX_ENV_BYTES = 64 * 1024
MAX_SECRET_BYTES = 8 * 1024
ASSIGNMENT_RE = re.compile(
    r'^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=',
)
SECRET_FILES = {
    'DJANGO_SECRET_KEY': 'django-secret-key',
    'TWO_FACTOR_KEYS': 'two-factor-keys',
    'ADMIN_AUDIT_KEYS': 'admin-audit-keys',
    'DB_PASSWORD': 'db-password',
    'NVIDIA_API_KEY': 'nvidia-api-key',
    'SMTP_PASS': 'smtp-password',
}


class CredentialError(ValueError):
    """A content-free application credential validation error."""


def _regular_file(path, *, maximum, label):
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CredentialError(f'{label} is unavailable') from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise CredentialError(f'{label} is not a regular nonsymlink file')
    if path.resolve(strict=True) != path:
        raise CredentialError(f'{label} is not canonical')
    if not 1 <= metadata.st_size <= maximum:
        raise CredentialError(f'{label} has an unsafe size')
    return metadata


def _read_environment(path):
    _regular_file(path, maximum=MAX_ENV_BYTES, label='runtime configuration')
    try:
        raw = path.read_bytes()
        text = raw.decode('utf-8')
    except (OSError, UnicodeDecodeError) as exc:
        raise CredentialError('runtime configuration is unreadable') from exc
    if '\x00' in text:
        raise CredentialError('runtime configuration contains an invalid byte')
    assignments = {}
    for index, line in enumerate(text.splitlines(keepends=True)):
        match = ASSIGNMENT_RE.match(line)
        if match:
            assignments.setdefault(match.group('name'), []).append(index)
    try:
        values = dotenv_values(path, interpolate=False)
    except (OSError, ValueError) as exc:
        raise CredentialError('runtime configuration cannot be parsed') from exc
    return text, assignments, values


def _validate_secret(name, value):
    if not isinstance(value, str) or not value:
        raise CredentialError(f'{name} is missing or empty')
    try:
        encoded = value.encode('utf-8')
    except UnicodeEncodeError as exc:
        raise CredentialError(f'{name} is not valid UTF-8') from exc
    if len(encoded) > MAX_SECRET_BYTES:
        raise CredentialError(f'{name} exceeds the safe size bound')
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise CredentialError(f'{name} contains a control character')
    return encoded


def _write_all(descriptor, payload):
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written < 1:
            raise CredentialError('credential staging write failed')
        view = view[written:]


def stage_credentials(env_file, staging_dir, output_env, final_dir):
    """Convert one exact inline assignment per secret into file pointers."""
    text, assignments, values = _read_environment(env_file)
    if not final_dir.is_absolute() or final_dir.resolve(strict=False) != final_dir:
        raise CredentialError('credential destination is not canonical')
    if output_env.exists() or output_env.is_symlink():
        raise CredentialError('staged runtime configuration already exists')
    if not staging_dir.is_dir() or staging_dir.is_symlink():
        raise CredentialError('credential staging directory is unsafe')
    if any(staging_dir.iterdir()):
        raise CredentialError('credential staging directory is not empty')

    replacements = {}
    for name, filename in SECRET_FILES.items():
        if len(assignments.get(name, [])) != 1:
            raise CredentialError(f'{name} must have exactly one inline assignment')
        if assignments.get(f'{name}_FILE'):
            raise CredentialError(f'{name} has ambiguous direct and file sources')
        payload = _validate_secret(name, values.get(name))
        target = staging_dir / filename
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            _write_all(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        replacements[assignments[name][0]] = f'{name}_FILE={final_dir / filename}'

    output_lines = []
    for index, line in enumerate(text.splitlines(keepends=True)):
        replacement = replacements.get(index)
        if replacement is None:
            output_lines.append(line)
            continue
        newline = '\r\n' if line.endswith('\r\n') else '\n' if line.endswith('\n') else ''
        output_lines.append(replacement + newline)
    descriptor = os.open(output_env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _write_all(descriptor, ''.join(output_lines).encode('utf-8'))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def check_credentials(env_file, credential_dir, owner, group, env_owner):
    """Validate metadata and pointers without reading credential contents."""
    env_metadata = _regular_file(
        env_file, maximum=MAX_ENV_BYTES, label='runtime configuration',
    )
    expected_uid = pwd.getpwnam(owner).pw_uid
    expected_gid = grp.getgrnam(group).gr_gid
    if (env_metadata.st_uid, env_metadata.st_gid, stat.S_IMODE(env_metadata.st_mode)) != (
        pwd.getpwnam(env_owner).pw_uid,
        expected_gid,
        0o640,
    ):
        raise CredentialError('runtime configuration metadata is unsafe')

    _, assignments, values = _read_environment(env_file)
    try:
        directory_metadata = credential_dir.lstat()
    except OSError as exc:
        raise CredentialError('credential directory is unavailable') from exc
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or credential_dir.is_symlink()
        or credential_dir.resolve(strict=True) != credential_dir
        or directory_metadata.st_uid != expected_uid
        or directory_metadata.st_gid != expected_gid
        or stat.S_IMODE(directory_metadata.st_mode) != 0o750
    ):
        raise CredentialError('credential directory metadata is unsafe')

    if {entry.name for entry in credential_dir.iterdir()} != set(SECRET_FILES.values()):
        raise CredentialError('credential directory entries do not match the manifest')
    for name, filename in SECRET_FILES.items():
        if assignments.get(name):
            raise CredentialError(f'{name} must not remain inline')
        file_name = f'{name}_FILE'
        if len(assignments.get(file_name, [])) != 1:
            raise CredentialError(f'{file_name} must have exactly one assignment')
        expected_path = credential_dir / filename
        if values.get(file_name) != str(expected_path):
            raise CredentialError(f'{file_name} does not select the managed credential')
        metadata = _regular_file(
            expected_path, maximum=MAX_SECRET_BYTES, label=f'{name} credential',
        )
        if (
            metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o640
        ):
            raise CredentialError(f'{name} credential metadata is unsafe')


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--credential-dir', type=Path, required=True)
    parser.add_argument('--owner', default='root')
    parser.add_argument('--group', default='aichat')
    parser.add_argument('--env-owner', default='micu')
    parser.add_argument('--stage-output-env', type=Path)
    parser.add_argument('--stage-credential-dir', type=Path)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        if args.stage_output_env or args.stage_credential_dir:
            if not args.stage_output_env or not args.stage_credential_dir:
                raise CredentialError('both staging paths are required')
            stage_credentials(
                args.env_file,
                args.stage_credential_dir,
                args.stage_output_env,
                args.credential_dir,
            )
            print('Application credentials staged without emitting values.')
        else:
            check_credentials(
                args.env_file,
                args.credential_dir,
                args.owner,
                args.group,
                args.env_owner,
            )
            print('Application credential boundary is valid.')
    except (CredentialError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
