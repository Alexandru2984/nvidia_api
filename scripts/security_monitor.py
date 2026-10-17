#!/usr/bin/python3
"""Detect high-signal AI Chat Hub security/backup conditions and alert Telegram.

The monitor sends only fixed event names and counts. It never forwards log lines,
IP addresses, usernames, prompts, credentials, or attachment names.
"""
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DUMP_RE = re.compile(r'^nvidia_db_\d{8}_\d{6}(?:_\d+)?\.sql\.gz$')
BACKUP_MAX_AGE_SECONDS = 30 * 60 * 60
RESTORE_MAX_AGE_SECONDS = 8 * 24 * 60 * 60
CLAMAV_DATABASE_MAX_AGE_SECONDS = 30 * 60 * 60
CLAMAV_DAILY_DATABASE_NAMES = frozenset({'daily.cvd', 'daily.cld'})
JOURNAL_WINDOW = '6 minutes ago'
RELEASE_MANIFEST = '.release-manifest.sha256'
FRONTEND_MANIFEST = RELEASE_MANIFEST
FRONTEND_MAX_FILES = 5_000
FRONTEND_MAX_BYTES = 256 * 1024 * 1024
BACKEND_MAX_FILES = 5_000
BACKEND_MAX_BYTES = 128 * 1024 * 1024
PYTHON_ENV_MAX_FILES = 20_000
PYTHON_ENV_MAX_BYTES = 512 * 1024 * 1024
MAX_RELEASE_DIRECTORIES = 3
SAFE_RELEASE_NAME_RE = re.compile(r'^release-\d{8}T\d{6}_\d+$')
SAFE_LEGACY_NAME_RE = re.compile(r'^legacy-\d{8}T\d{6}_\d+$')
SAFE_RELEASE_PATH_RE = re.compile(r'^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$')
PYTHON_ENV_SAFE_PATH_RE = re.compile(
    r'^(?:[A-Za-z0-9._\[\]-]+/)*[A-Za-z0-9._\[\]-]+$',
)
PARSER_MAGIC = b'AIP1'
PARSER_REQUEST = struct.Struct('!4sBII')
PARSER_RESPONSE = struct.Struct('!4sBI')
JOURNALCTL_PATH = '/usr/bin/journalctl'
GETFACL_PATH = '/usr/bin/getfacl'


def _hash_file(path):
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _has_exact_acl(path, expected_entries):
    """Require the complete access ACL, not merely permissive mode-bit masks."""
    try:
        result = subprocess.run(
            [GETFACL_PATH, '--access', '--omit-header', '--numeric', '--absolute-names',
             os.fspath(path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode or result.stderr.strip():
        return False
    entries = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return len(entries) == len(expected_entries) and set(entries) == set(expected_entries)


def _evaluate_release(
    live_path,
    release_root,
    *,
    issue_key,
    issue_message,
    max_files,
    max_bytes,
    manifest_max_bytes=1024 * 1024,
    safe_path_re=SAFE_RELEASE_PATH_RE,
    executable_files=frozenset(),
    required_files=frozenset(),
    expected_uid=0,
    expected_gid=0,
):
    """Fail closed if an active release differs from its root-created manifest."""
    issue = {issue_key: issue_message}
    live_path = Path(live_path)
    release_root = Path(release_root)
    try:
        live_info = live_path.lstat()
        if not stat.S_ISLNK(live_info.st_mode):
            return issue
        if live_info.st_uid != expected_uid or live_info.st_gid != expected_gid:
            return issue

        trusted_root = release_root.resolve(strict=True)
        target = live_path.resolve(strict=True)
        trusted_root_info = trusted_root.lstat()
        if (
            not stat.S_ISDIR(trusted_root_info.st_mode)
            or trusted_root_info.st_uid != expected_uid
            or trusted_root_info.st_gid != expected_gid
            or stat.S_IMODE(trusted_root_info.st_mode) != 0o755
        ):
            return issue
        if target.parent != trusted_root or not SAFE_RELEASE_NAME_RE.fullmatch(target.name):
            return issue

        manifest_path = target / RELEASE_MANIFEST
        actual_files = {}
        total_bytes = 0
        for directory, dirnames, filenames in os.walk(target, followlinks=False):
            directory_path = Path(directory)
            directory_info = directory_path.lstat()
            if (
                not stat.S_ISDIR(directory_info.st_mode)
                or directory_info.st_uid != expected_uid
                or directory_info.st_gid != expected_gid
                or stat.S_IMODE(directory_info.st_mode) != 0o755
            ):
                return issue

            for name in dirnames + filenames:
                path = directory_path / name
                relative = path.relative_to(target).as_posix()
                if not safe_path_re.fullmatch(relative):
                    return issue
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    return issue
                if info.st_uid != expected_uid or info.st_gid != expected_gid:
                    return issue
                if stat.S_ISDIR(info.st_mode):
                    if stat.S_IMODE(info.st_mode) != 0o755:
                        return issue
                    continue
                expected_mode = 0o755 if relative in executable_files else 0o644
                if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != expected_mode:
                    return issue
                if relative == RELEASE_MANIFEST:
                    continue
                total_bytes += info.st_size
                if len(actual_files) >= max_files or total_bytes > max_bytes:
                    return issue
                actual_files[f'./{relative}'] = path

        manifest_info = manifest_path.lstat()
        if not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_size > manifest_max_bytes:
            return issue
        expected_hashes = {}
        for line in manifest_path.read_text(encoding='ascii').splitlines():
            digest, separator, relative = line.partition('  ')
            if (
                separator != '  '
                or not re.fullmatch(r'[0-9a-f]{64}', digest)
                or not relative.startswith('./')
                or not safe_path_re.fullmatch(relative[2:])
                or relative in expected_hashes
            ):
                return issue
            expected_hashes[relative] = digest
        if not expected_hashes or set(expected_hashes) != set(actual_files):
            return issue
        if not {f'./{path}' for path in required_files}.issubset(actual_files):
            return issue
        if any(_hash_file(actual_files[path]) != digest for path, digest in expected_hashes.items()):
            return issue
        return {}
    except (OSError, UnicodeError, ValueError):
        return issue


def evaluate_frontend_release(
    live_path,
    release_root,
    *,
    expected_uid=0,
    expected_gid=0,
):
    return _evaluate_release(
        live_path,
        release_root,
        issue_key='frontend_integrity',
        issue_message=(
            'The active frontend release, ownership, permissions or manifest failed validation.'
        ),
        max_files=FRONTEND_MAX_FILES,
        max_bytes=FRONTEND_MAX_BYTES,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def evaluate_backend_release(
    live_path,
    release_root,
    *,
    expected_uid=0,
    expected_gid=0,
):
    return _evaluate_release(
        live_path,
        release_root,
        issue_key='backend_integrity',
        issue_message=(
            'The active backend release, ownership, permissions or manifest failed validation.'
        ),
        max_files=BACKEND_MAX_FILES,
        max_bytes=BACKEND_MAX_BYTES,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def evaluate_python_environment_release(
    live_path,
    release_root,
    *,
    expected_uid=0,
    expected_gid=0,
):
    return _evaluate_release(
        live_path,
        release_root,
        issue_key='python_environment_integrity',
        issue_message=(
            'The active Python environment, ownership, permissions or manifest failed validation.'
        ),
        max_files=PYTHON_ENV_MAX_FILES,
        max_bytes=PYTHON_ENV_MAX_BYTES,
        manifest_max_bytes=4 * 1024 * 1024,
        safe_path_re=PYTHON_ENV_SAFE_PATH_RE,
        executable_files=frozenset({'bin/python'}),
        required_files=frozenset({
            '.release-commit',
            '.release-requirements.lock',
            '.release-requirements.sha256',
            '.release-sbom.cdx.json',
        }),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def evaluate_release_retention(live_path, release_root, *, issue_key):
    issue = {
        issue_key: (
            f'The executable release root exceeds {MAX_RELEASE_DIRECTORIES} entries '
            'or contains an unsafe entry.'
        ),
    }
    live_path = Path(live_path)
    release_root = Path(release_root)
    try:
        root = release_root.resolve(strict=True)
        target = live_path.resolve(strict=True)
        if target.parent != root or not SAFE_RELEASE_NAME_RE.fullmatch(target.name):
            return issue
        entries = []
        for entry in release_root.iterdir():
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                return issue
            if not (
                SAFE_RELEASE_NAME_RE.fullmatch(entry.name)
                or SAFE_LEGACY_NAME_RE.fullmatch(entry.name)
            ):
                return issue
            entries.append(entry)
        if target not in entries or len(entries) > MAX_RELEASE_DIRECTORIES:
            return issue
        return {}
    except (OSError, RuntimeError, ValueError):
        return issue


def evaluate_clamav_database(database_dir, now=None):
    """Require a recent, non-writable official daily-signature database."""
    now = now or time.time()
    database_dir = Path(database_dir)
    integrity_issue = {
        'malware_database_integrity': (
            'The ClamAV signature database is missing or has unsafe permissions.'
        ),
    }
    try:
        directory_info = database_dir.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or stat.S_ISLNK(directory_info.st_mode)
            or stat.S_IMODE(directory_info.st_mode) & 0o022
        ):
            return integrity_issue
        databases = []
        for name in CLAMAV_DAILY_DATABASE_NAMES:
            path = database_dir / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or stat.S_IMODE(info.st_mode) & 0o022
            ):
                return integrity_issue
            databases.append(info)
        if not databases:
            return integrity_issue
        newest = max(info.st_mtime for info in databases)
        if now - newest > CLAMAV_DATABASE_MAX_AGE_SECONDS:
            age_hours = max(0, int((now - newest) // 3600))
            return {
                'malware_database_stale': (
                    f'The newest ClamAV daily-signature database is {age_hours} hours old.'
                ),
            }
        return {}
    except (OSError, ValueError):
        return integrity_issue


def evaluate_clamav_socket(socket_path, timeout_seconds=3):
    """Require an authenticated local socket shape and an exact clamd PONG."""
    issue = {'malware_scanner_health': 'The local attachment malware scanner is unavailable.'}
    socket_path = Path(socket_path)
    try:
        info = socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o007:
            return issue
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds)
            client.connect(str(socket_path))
            client.sendall(b'zPING\0')
            reply = bytearray()
            while len(reply) <= 16:
                chunk = client.recv(17 - len(reply))
                if not chunk:
                    break
                reply.extend(chunk)
                terminator = reply.find(b'\0')
                if terminator >= 0:
                    return {} if bytes(reply[:terminator]) == b'PONG' else issue
        return issue
    except (OSError, ValueError):
        return issue


def evaluate_document_parser_socket(socket_path, timeout_seconds=3):
    """Require the private socket shape and exact parser health response."""
    issue = {'document_parser_health': 'The isolated document parser is unavailable.'}
    socket_path = Path(socket_path)
    try:
        info = socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o660:
            return issue
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds)
            client.connect(str(socket_path))
            client.sendall(PARSER_REQUEST.pack(PARSER_MAGIC, 0, 0, 0))
            response = bytearray()
            while len(response) < PARSER_RESPONSE.size:
                chunk = client.recv(PARSER_RESPONSE.size - len(response))
                if not chunk:
                    return issue
                response.extend(chunk)
            if bytes(response) != PARSER_RESPONSE.pack(PARSER_MAGIC, 0, 0):
                return issue
            if client.recv(1):
                return issue
        return {}
    except (OSError, ValueError, struct.error):
        return issue


def evaluate_backend_origin_socket(socket_path, *, expected_uid, expected_gid):
    """Require the web origin to be a permissioned Unix socket."""
    issue = {
        'backend_origin_socket': (
            'The backend origin socket is missing or has unsafe ownership or permissions.'
        ),
    }
    try:
        path = Path(socket_path)
        parent_info = path.parent.lstat()
        info = path.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or stat.S_ISLNK(parent_info.st_mode)
            or parent_info.st_uid != expected_uid
            or parent_info.st_gid != expected_gid
            or stat.S_IMODE(parent_info.st_mode) != 0o750
            or not stat.S_ISSOCK(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o660
        ):
            return issue
        return {}
    except (OSError, ValueError):
        return issue


def evaluate_forbidden_backend_tcp(host='127.0.0.1', port=8501, timeout_seconds=1):
    """Alert if the retired direct backend TCP origin becomes reachable."""
    issue = {
        'backend_tcp_origin': (
            'The retired direct backend TCP origin is listening again.'
        ),
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds)
            return issue if client.connect_ex((host, port)) == 0 else {}
    except (OSError, ValueError):
        return issue


def evaluate_document_parser_installation(
    backend_live,
    service_path,
    worker_path,
    *,
    expected_uid=0,
    expected_gid=0,
):
    """Bind installed parser executables to the manifest-checked backend release."""
    issue = {
        'document_parser_integrity': (
            'The installed document parser differs from the active backend release.'
        ),
    }
    try:
        backend_live = Path(backend_live)
        if not stat.S_ISLNK(backend_live.lstat().st_mode):
            return issue
        release = backend_live.resolve(strict=True)
        pairs = (
            (Path(service_path), release / 'chat' / 'document_parser_service.py'),
            (Path(worker_path), release / 'chat' / 'document_worker.py'),
        )
        for installed, source in pairs:
            installed_info = installed.lstat()
            source_info = source.lstat()
            if (
                not stat.S_ISREG(installed_info.st_mode)
                or stat.S_ISLNK(installed_info.st_mode)
                or installed_info.st_uid != expected_uid
                or installed_info.st_gid != expected_gid
                or stat.S_IMODE(installed_info.st_mode) != 0o755
                or not 1 <= installed_info.st_size <= 1024 * 1024
                or not stat.S_ISREG(source_info.st_mode)
                or stat.S_ISLNK(source_info.st_mode)
                or source_info.st_uid != expected_uid
                or source_info.st_gid != expected_gid
                or stat.S_IMODE(source_info.st_mode) != 0o644
                or source_info.st_size != installed_info.st_size
                or _hash_file(source) != _hash_file(installed)
            ):
                return issue
        return {}
    except (OSError, RuntimeError, ValueError):
        return issue


def read_journal():
    result = subprocess.run(
        [JOURNALCTL_PATH,
         '--unit=aichat-backend.service', '--unit=aichat-maintenance.service',
         '--unit=aichat-model-probe.service', '--unit=aichat-document-parser.service',
         '--unit=aichat-config-watch.service',
         f'--since={JOURNAL_WINDOW}',
         '--output=cat', '--no-pager', '--quiet'],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if result.returncode:
        raise RuntimeError('journal query failed')
    return result.stdout


def evaluate(
    backup_dir,
    restore_log,
    journal,
    now=None,
    *,
    frontend_live=None,
    frontend_release_root=None,
    frontend_expected_uid=0,
    frontend_expected_gid=0,
    backend_live=None,
    backend_release_root=None,
    backend_expected_uid=0,
    backend_expected_gid=0,
    backend_socket=None,
    backend_socket_expected_uid=0,
    backend_socket_expected_gid=0,
    forbidden_backend_tcp=None,
    python_environment_live=None,
    python_environment_release_root=None,
    python_environment_expected_uid=0,
    python_environment_expected_gid=0,
    scanner_database_dir=None,
    scanner_socket=None,
    document_parser_socket=None,
    document_parser_service=None,
    document_parser_worker=None,
    backup_expected_uid=None,
    backup_expected_gid=None,
    backup_monitor_uid=None,
):
    now = now or time.time()
    issues = {}
    backup_dir = Path(backup_dir)
    restore_log = Path(restore_log)

    if scanner_database_dir is not None:
        issues.update(evaluate_clamav_database(scanner_database_dir, now))
    if scanner_socket is not None:
        issues.update(evaluate_clamav_socket(scanner_socket))
    if document_parser_socket is not None:
        issues.update(evaluate_document_parser_socket(document_parser_socket))
    if document_parser_service is not None or document_parser_worker is not None:
        if (
            document_parser_service is None
            or document_parser_worker is None
            or backend_live is None
        ):
            issues['document_parser_integrity'] = (
                'The document parser integrity monitor is misconfigured.'
            )
        else:
            issues.update(evaluate_document_parser_installation(
                backend_live,
                document_parser_service,
                document_parser_worker,
                expected_uid=backend_expected_uid,
                expected_gid=backend_expected_gid,
            ))

    if backend_socket is not None:
        issues.update(evaluate_backend_origin_socket(
            backend_socket,
            expected_uid=backend_socket_expected_uid,
            expected_gid=backend_socket_expected_gid,
        ))
    if forbidden_backend_tcp is not None:
        issues.update(evaluate_forbidden_backend_tcp(*forbidden_backend_tcp))

    if frontend_live is not None or frontend_release_root is not None:
        if frontend_live is None or frontend_release_root is None:
            issues['frontend_integrity'] = 'The frontend integrity monitor is misconfigured.'
        else:
            issues.update(evaluate_frontend_release(
                frontend_live,
                frontend_release_root,
                expected_uid=frontend_expected_uid,
                expected_gid=frontend_expected_gid,
            ))
            issues.update(evaluate_release_retention(
                frontend_live,
                frontend_release_root,
                issue_key='frontend_release_retention',
            ))

    if backend_live is not None or backend_release_root is not None:
        if backend_live is None or backend_release_root is None:
            issues['backend_integrity'] = 'The backend integrity monitor is misconfigured.'
        else:
            issues.update(evaluate_backend_release(
                backend_live,
                backend_release_root,
                expected_uid=backend_expected_uid,
                expected_gid=backend_expected_gid,
            ))
            issues.update(evaluate_release_retention(
                backend_live,
                backend_release_root,
                issue_key='backend_release_retention',
            ))

    if python_environment_live is not None or python_environment_release_root is not None:
        if python_environment_live is None or python_environment_release_root is None:
            issues['python_environment_integrity'] = (
                'The Python environment integrity monitor is misconfigured.'
            )
        else:
            issues.update(evaluate_python_environment_release(
                python_environment_live,
                python_environment_release_root,
                expected_uid=python_environment_expected_uid,
                expected_gid=python_environment_expected_gid,
            ))
            issues.update(evaluate_release_retention(
                python_environment_live,
                python_environment_release_root,
                issue_key='python_environment_release_retention',
            ))

    if not backup_dir.is_dir() or backup_dir.is_symlink():
        issues['backup_missing'] = 'Backup directory is missing or unsafe.'
    else:
        backup_info = backup_dir.stat()
        if backup_monitor_uid is None:
            if stat.S_IMODE(backup_info.st_mode) & 0o077:
                issues['backup_directory_permissions'] = (
                    'Backup directory has group/other permissions.'
                )
        else:
            expected_acl = {
                'user::rwx',
                f'user:{backup_monitor_uid}:r-x',
                'group::---',
                'mask::r-x',
                'other::---',
            }
            if (
                stat.S_IMODE(backup_info.st_mode) != 0o750
                or backup_info.st_uid != backup_expected_uid
                or backup_info.st_gid != backup_expected_gid
                or not _has_exact_acl(backup_dir, expected_acl)
            ):
                issues['backup_directory_permissions'] = (
                    'Backup directory ownership, permissions or monitor ACL is unsafe.'
                )
        dumps = [path for path in backup_dir.iterdir()
                 if DUMP_RE.fullmatch(path.name) and path.is_file() and not path.is_symlink()]
        if not dumps:
            issues['backup_missing'] = 'No valid database backup was found.'
        else:
            latest = max(dumps, key=lambda path: path.stat().st_mtime)
            info = latest.stat()
            age_hours = max(0, int((now - info.st_mtime) // 3600))
            if now - info.st_mtime > BACKUP_MAX_AGE_SECONDS:
                issues['backup_stale'] = f'Newest database backup is {age_hours} hours old.'
            if (
                stat.S_IMODE(info.st_mode) != 0o600
                or (
                    backup_monitor_uid is not None
                    and (
                        info.st_uid != backup_expected_uid
                        or info.st_gid != backup_expected_gid
                    )
                )
            ):
                issues['backup_permissions'] = 'Newest database backup has group/other permissions.'

    if not restore_log.is_file() or restore_log.is_symlink():
        issues['restore_missing'] = 'No successful restore-drill log was found.'
    else:
        info = restore_log.stat()
        age_days = max(0, int((now - info.st_mtime) // 86400))
        if now - info.st_mtime > RESTORE_MAX_AGE_SECONDS:
            issues['restore_stale'] = f'Last restore drill is {age_days} days old.'
        try:
            tail = restore_log.read_text(encoding='utf-8', errors='replace')[-4096:]
        except OSError:
            tail = ''
        lines = [line for line in tail.splitlines() if line.strip()]
        if not lines or 'restore drill ok:' not in lines[-1]:
            issues['restore_failed'] = 'Latest restore-drill log has no success marker.'
        if backup_monitor_uid is None:
            if stat.S_IMODE(info.st_mode) & 0o077:
                issues['restore_log_permissions'] = (
                    'Restore-drill log has group/other permissions.'
                )
        else:
            expected_acl = {
                'user::rw-',
                f'user:{backup_monitor_uid}:r--',
                'group::---',
                'mask::r--',
                'other::---',
            }
            if (
                stat.S_IMODE(info.st_mode) != 0o640
                or info.st_uid != backup_expected_uid
                or info.st_gid != backup_expected_gid
                or not _has_exact_acl(restore_log, expected_acl)
            ):
                issues['restore_log_permissions'] = (
                    'Restore-drill log ownership, permissions or monitor ACL is unsafe.'
                )

    auth_failures = (
        journal.count('event=auth_failed')
        + journal.count('event=recent_auth_failed')
    )
    rate_limits = journal.count('event=rate_limit')
    admin_denied = journal.count('event=admin_access_denied')
    admin_changes = journal.count('event=admin_change')
    unmetered_usage = journal.count('event=ai_usage_unmetered')
    token_overruns = journal.count('event=ai_token_reservation_exceeded')
    object_quota_blocks = journal.count('event=chat_object_quota_blocked')
    session_registry_mismatches = journal.count('event=session_registry_mismatch')
    session_limit_enforcements = journal.count('event=session_limit_enforced')
    invite_rejections = journal.count('event=registration_invite_rejected')
    attachment_rejections = journal.count('event=attachment_capability_rejected')
    malware_rejections = journal.count('event=attachment_malware_rejected')
    scanner_unavailable = journal.count('event=attachment_scanner_unavailable')
    parser_unavailable = journal.count('event=attachment_parser_unavailable')
    parser_failures = journal.count('event=document_parser_failure')
    provider_protocol_rejections = journal.count('event=provider_protocol_rejected')
    two_factor_key_errors = journal.count('event=two_factor_key_error')
    model_status_invalid = journal.count('event=model_status_invalid')
    model_probe_degraded = journal.count('event=model_probe_degraded')
    model_probe_authorization = journal.count('event=model_probe_authorization_failed')
    protected_config_changes = journal.count('event=protected_config_changed')
    generation_idempotency_conflicts = journal.count(
        'event=generation_idempotency_conflict'
    )
    generation_interruptions = journal.count('event=generation_request_interrupted')
    account_exports = journal.count('event=account_export_completed')
    account_export_bound_failures = journal.count('event=account_export_bound_exceeded')
    maintenance_failures = journal.count(
        'aichat-maintenance.service: Failed with result'
    )
    invite_consumed = journal.count('event=registration_invite_consumed')
    registrations_verified = journal.count('event=registration_verified')
    internal_errors = journal.count('Internal Server Error:') + journal.count('[ERROR]')
    if auth_failures >= int(os.environ.get('AUTH_FAILURE_ALERT_THRESHOLD', '10')):
        issues['auth_burst'] = (
            f'{auth_failures} failed authentication attempts were detected in six minutes.'
        )
    if rate_limits >= int(os.environ.get('RATE_LIMIT_ALERT_THRESHOLD', '20')):
        issues['rate_limit_burst'] = f'{rate_limits} rate-limit events were detected in six minutes.'
    if admin_denied >= int(os.environ.get('ADMIN_DENIED_ALERT_THRESHOLD', '10')):
        issues['admin_probe_burst'] = f'{admin_denied} denied admin requests were detected in six minutes.'
    if 'event=admin_access ' in journal or 'event=admin_login ' in journal:
        issues['admin_access'] = 'A successful Django admin access was detected.'
    if admin_changes:
        issues['admin_change'] = f'{admin_changes} privileged admin changes were detected.'
    if 'event=admin_audit_integrity_failed' in journal:
        issues['admin_audit_integrity'] = 'The privileged-change audit trail failed integrity checks.'
    if 'event=two_factor_disabled' in journal:
        issues['two_factor_disabled'] = 'Two-factor authentication was disabled for an account.'
    if 'event=ai_budget_blocked scope=global' in journal:
        issues['global_budget'] = 'The service-wide daily AI budget was exhausted.'
    if unmetered_usage >= int(os.environ.get('UNMETERED_USAGE_ALERT_THRESHOLD', '3')):
        issues['unmetered_ai_usage'] = (
            f'{unmetered_usage} AI calls had no valid provider usage in six minutes.'
        )
    if token_overruns:
        issues['token_reservation_overrun'] = (
            f'{token_overruns} AI calls exceeded their token reservation in six minutes.'
        )
    if object_quota_blocks >= int(os.environ.get('OBJECT_QUOTA_ALERT_THRESHOLD', '1')):
        issues['chat_object_quota'] = (
            f'{object_quota_blocks} chat object quota blocks were detected in six minutes.'
        )
    if session_registry_mismatches:
        issues['session_registry_mismatch'] = (
            f'{session_registry_mismatches} authenticated session registry mismatches were detected.'
        )
    if session_limit_enforcements >= int(os.environ.get('SESSION_LIMIT_ALERT_THRESHOLD', '3')):
        issues['session_limit_burst'] = (
            f'{session_limit_enforcements} per-account session limits were enforced in six minutes.'
        )
    if invite_rejections >= int(os.environ.get('INVITE_REJECTION_ALERT_THRESHOLD', '5')):
        issues['invite_rejection_burst'] = (
            f'{invite_rejections} invalid invitation attempts were detected in six minutes.'
        )
    if attachment_rejections >= int(os.environ.get('ATTACHMENT_REJECTION_ALERT_THRESHOLD', '5')):
        issues['attachment_capability_burst'] = (
            f'{attachment_rejections} incompatible attachment attempts were detected in six minutes.'
        )
    if malware_rejections:
        issues['attachment_malware'] = (
            f'{malware_rejections} attachment malware detections were recorded in six minutes.'
        )
    if scanner_unavailable:
        issues['attachment_scanner_unavailable'] = (
            'Attachment malware scanning was unavailable during a request.'
        )
    if parser_unavailable:
        issues['attachment_parser_unavailable'] = (
            'Isolated document parsing was unavailable during an upload.'
        )
    if parser_failures:
        issues['document_parser_failure'] = (
            f'{parser_failures} isolated document-parser failures were detected in six minutes.'
        )
    if provider_protocol_rejections:
        issues['provider_protocol_rejected'] = (
            f'{provider_protocol_rejections} malformed or redirected provider responses '
            'were rejected in six minutes.'
        )
    if two_factor_key_errors:
        issues['two_factor_key_error'] = (
            f'{two_factor_key_errors} stored two-factor artifacts could not be opened safely.'
        )
    if model_status_invalid:
        issues['model_status_invalid'] = 'The runtime model-status file failed validation.'
    if model_probe_degraded:
        issues['model_probe_degraded'] = 'The NVIDIA model probe had inconclusive results.'
    if model_probe_authorization:
        issues['model_probe_authorization'] = (
            'The NVIDIA model probe encountered an authorization or entitlement failure.'
        )
    if protected_config_changes:
        issues['protected_config_changed'] = (
            'A protected AI Chat Hub configuration or monitor file changed.'
        )
    if generation_idempotency_conflicts >= int(
        os.environ.get('GENERATION_IDEMPOTENCY_CONFLICT_ALERT_THRESHOLD', '3')
    ):
        issues['generation_idempotency_conflict'] = (
            f'{generation_idempotency_conflicts} reused generation keys had mismatched '
            'request data in six minutes.'
        )
    if generation_interruptions:
        issues['generation_interrupted'] = (
            f'{generation_interruptions} generation requests lost their durable lease '
            'in six minutes.'
        )
    if account_exports:
        issues['account_export_completed'] = (
            f'{account_exports} account data exports completed in six minutes.'
        )
    if account_export_bound_failures:
        issues['account_export_bound_exceeded'] = (
            f'{account_export_bound_failures} account data exports exceeded their validated '
            'streaming bound in six minutes.'
        )
    if maintenance_failures:
        issues['maintenance_failed'] = (
            'The daily expired-data and chat-retention maintenance job failed.'
        )
    if invite_consumed:
        issues['registration_invite_consumed'] = (
            f'{invite_consumed} registration invitations were consumed in six minutes.'
        )
    if registrations_verified:
        issues['registration_verified'] = (
            f'{registrations_verified} new accounts completed verification in six minutes.'
        )
    if internal_errors >= int(os.environ.get('INTERNAL_ERROR_ALERT_THRESHOLD', '3')):
        issues['error_burst'] = f'{internal_errors} backend errors were detected in six minutes.'
    return issues


def parse_monitor_credentials(path):
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as exc:
        raise RuntimeError('monitor notification credentials are unavailable') from exc
    mode = stat.S_IMODE(info.st_mode)
    ordinary_private_file = mode & 0o077 == 0 and info.st_uid in {0, os.geteuid()}
    credentials_directory = os.environ.get('CREDENTIALS_DIRECTORY', '')
    systemd_credential = (
        bool(credentials_directory)
        and Path(credentials_directory).is_absolute()
        and path.parent == Path(credentials_directory)
        and mode == 0o440
        and info.st_uid == 0
        and info.st_gid == 0
        and _has_exact_acl(path, {
            'user::r--',
            f'user:{os.geteuid()}:r--',
            'group::---',
            'mask::r--',
            'other::---',
        })
    )
    if (
        not stat.S_ISREG(info.st_mode)
        or not (ordinary_private_file or systemd_credential)
        or not 1 <= info.st_size <= 64 * 1024
    ):
        raise RuntimeError('monitor notification credentials are unsafe')
    wanted = {'BOT_TOKEN', 'CHAT_ID'}
    values = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if key not in wanted:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    if not values.get('BOT_TOKEN') or not values.get('CHAT_ID'):
        raise RuntimeError('monitor notification credentials are missing')
    return values


def send_telegram(credentials_path, text):
    credentials = parse_monitor_credentials(credentials_path)
    data = urllib.parse.urlencode({
        'chat_id': credentials['CHAT_ID'],
        'text': text,
        'disable_web_page_preview': 'true',
    }).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{credentials['BOT_TOKEN']}/sendMessage",
        data=data,
        method='POST',
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status != 200:
                raise RuntimeError('notification service returned a non-200 response')
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f'notification service returned HTTP {exc.code}') from None
    except urllib.error.URLError:
        raise RuntimeError('notification service could not be reached') from None


def load_state(path):
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.geteuid()
        ):
            raise RuntimeError('monitor state has unsafe ownership or permissions')
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            raise TypeError
        return data
    except FileNotFoundError:
        return {'active': [], 'last_sent': {}}
    except RuntimeError:
        raise
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError('monitor state is invalid') from None


def save_state(path, state):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode='w', encoding='utf-8', dir=path.parent, prefix='.state.', delete=False,
    ) as handle:
        json.dump(state, handle, sort_keys=True)
        handle.write('\n')
        temporary = Path(handle.name)
    temporary.chmod(0o600)
    temporary.replace(path)


def alert_text(issues, resolved=False):
    title = 'AI Chat Hub security monitor recovered' if resolved else 'AI Chat Hub security alert'
    lines = [title, datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')]
    lines.extend(f'- {key}: {value}' for key, value in sorted(issues.items()))
    lines.append('Runbook: /home/micu/nvidia/docs/INCIDENT_RESPONSE.md')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--test-notification', action='store_true')
    parser.add_argument('--backup-dir', default='/home/micu/backups/nvidia_db')
    parser.add_argument('--restore-log', default='/home/micu/backups/nvidia_db/restore-drill.log')
    parser.add_argument('--journal-file')
    parser.add_argument('--state-dir', default='/var/lib/aichat-security-monitor')
    parser.add_argument('--credentials', default='/home/micu/scripts/.env')
    parser.add_argument('--frontend-live', default='/var/www/aichat.micutu.com')
    parser.add_argument('--frontend-release-root', default='/var/www/aichat-releases')
    parser.add_argument('--backend-live', default='/opt/aichat-backend-current')
    parser.add_argument('--backend-release-root', default='/opt/aichat-backend-releases')
    parser.add_argument('--backend-socket', default='/run/aichat-backend/gunicorn.sock')
    parser.add_argument('--forbidden-backend-port', type=int, default=8501)
    parser.add_argument('--python-environment-live', default='/opt/aichat-python-current')
    parser.add_argument('--python-environment-release-root', default='/opt/aichat-python-envs')
    parser.add_argument('--scanner-database-dir', default='/var/lib/clamav')
    parser.add_argument('--scanner-socket', default='/run/clamav/clamd.ctl')
    parser.add_argument(
        '--document-parser-socket',
        default='/run/aichat-document-parser/parser.sock',
    )
    parser.add_argument(
        '--document-parser-service',
        default='/usr/local/libexec/aichat-document-parser',
    )
    parser.add_argument(
        '--document-parser-worker',
        default='/usr/local/libexec/aichat-document-worker',
    )
    args = parser.parse_args()

    try:
        if args.test_notification:
            text = (
                'AI Chat Hub security monitor test\n'
                + datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                + '\nNotification path is working; no incident is declared.'
            )
            send_telegram(args.credentials, text)
            print('test notification sent')
            return 0
        # Validate the systemd-delivered notification credential on every run,
        # not only when an alert happens. Otherwise a broken alert path could
        # remain latent while all monitored conditions are healthy.
        parse_monitor_credentials(args.credentials)
        journal = Path(args.journal_file).read_text(encoding='utf-8') if args.journal_file else read_journal()
        issues = evaluate(
            args.backup_dir,
            args.restore_log,
            journal,
            frontend_live=args.frontend_live,
            frontend_release_root=args.frontend_release_root,
            backend_live=args.backend_live,
            backend_release_root=args.backend_release_root,
            backend_socket=args.backend_socket,
            backend_socket_expected_uid=pwd.getpwnam('aichat').pw_uid,
            backend_socket_expected_gid=grp.getgrnam('aichat-origin').gr_gid,
            forbidden_backend_tcp=('127.0.0.1', args.forbidden_backend_port),
            python_environment_live=args.python_environment_live,
            python_environment_release_root=args.python_environment_release_root,
            scanner_database_dir=args.scanner_database_dir,
            scanner_socket=args.scanner_socket,
            document_parser_socket=args.document_parser_socket,
            document_parser_service=args.document_parser_service,
            document_parser_worker=args.document_parser_worker,
            backup_expected_uid=pwd.getpwnam('micu').pw_uid,
            backup_expected_gid=pwd.getpwnam('micu').pw_gid,
            backup_monitor_uid=pwd.getpwnam('aichat-monitor').pw_uid,
        )
        if args.dry_run:
            print(json.dumps(issues, indent=2, sort_keys=True))
            return 1 if issues else 0

        state_path = Path(args.state_dir) / 'state.json'
        state = load_state(state_path)
        previous = set(state.get('active', []))
        last_sent = state.get('last_sent', {})
        now = int(time.time())
        cooldown = int(os.environ.get('ALERT_COOLDOWN_SECONDS', '1800'))
        notify = {
            key: message for key, message in issues.items()
            if key not in previous or now - int(last_sent.get(key, 0)) >= cooldown
        }
        resolved_keys = previous - set(issues)

        if notify:
            send_telegram(args.credentials, alert_text(notify))
            for key in notify:
                last_sent[key] = now
        if resolved_keys:
            resolved = {key: 'Condition is no longer present.' for key in resolved_keys}
            send_telegram(args.credentials, alert_text(resolved, resolved=True))

        state['active'] = sorted(issues)
        state['last_sent'] = last_sent
        save_state(state_path, state)
        return 0
    except Exception as exc:  # noqa: BLE001 - final CLI boundary must fail closed
        print(f'security monitor failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
