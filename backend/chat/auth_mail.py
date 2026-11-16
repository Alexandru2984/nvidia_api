"""Single-host, crash-persistent SMTP admission independent of SQL rollback.

Only this module touches the private budget directory. Django cache eviction
does not touch these files. Horizontal deployments need a shared budget store.
"""
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import stat
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path

from django.conf import settings

from .json_boundary import strict_json_loads

security_log = logging.getLogger('security')
MAX_STATE_BYTES = 32 * 1024
MAX_RECIPIENTS = 1000


class AuthMailLimited(Exception):
    """An attempted delivery exceeded the fixed UTC-day allowance."""


class AuthMailUnavailable(Exception):
    """Budget integrity/durability could not be established; do not send."""


def _private(info, *, directory=False):
    expected = 0o700 if directory else 0o600
    shape = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if (not shape or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != expected
            or (not directory and info.st_nlink != 1)):
        raise ValueError('unsafe budget boundary')


def _read_state(directory_fd, today):
    try:
        fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=directory_fd)
    except FileNotFoundError:
        return _empty(today)
    with os.fdopen(fd, 'rb') as handle:
        _private(os.fstat(handle.fileno()))
        content = handle.read(MAX_STATE_BYTES + 1)
    if len(content) > MAX_STATE_BYTES:
        raise ValueError('oversized budget state')
    value = strict_json_loads(content, max_nodes=3000, max_depth=3)
    if not isinstance(value, dict) or set(value) != {'version', 'day', 'verification', 'reset', 'recipients'}:
        raise ValueError('invalid budget shape')
    if type(value['version']) is not int or value['version'] != 1:
        raise ValueError('invalid budget version')
    recorded_day = date.fromisoformat(value['day'])
    if recorded_day.isoformat() != value['day'] or recorded_day > today:
        raise ValueError('invalid budget date')
    counters = [value['verification'], value['reset']]
    recipients = value['recipients']
    if not isinstance(recipients, dict) or len(recipients) > MAX_RECIPIENTS:
        raise ValueError('invalid recipient counters')
    if any(not re.fullmatch(r'[0-9a-f]{64}', key) for key in recipients):
        raise ValueError('invalid recipient key')
    if any(type(count) is not int or not 0 <= count <= 1_000_000
           for count in counters + list(recipients.values())):
        raise ValueError('invalid budget counter')
    if sum(counters) != sum(recipients.values()):
        raise ValueError('inconsistent budget counters')
    return _empty(today) if recorded_day < today else value


def _empty(today):
    return {'version': 1, 'day': today.isoformat(), 'verification': 0, 'reset': 0, 'recipients': {}}


def _write_state(root, directory_fd, value):
    payload = json.dumps(value, separators=(',', ':'), sort_keys=True).encode('utf-8')
    if len(payload) > MAX_STATE_BYTES:
        raise ValueError('oversized budget output')
    fd, temporary = tempfile.mkstemp(prefix='.state-', dir=root)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(Path(temporary).name, 'state.json',
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _purge_temporary_states(directory_fd):
    # Under the shared lock there is no active writer. A process killed before
    # replace can leave an old recipient snapshot; do not retain it indefinitely.
    temporary = []
    with os.scandir(directory_fd) as entries:
        for index, entry in enumerate(entries):
            if index >= 128:
                raise ValueError('unexpected budget directory size')
            if entry.name in {'.lock', 'state.json'}:
                continue
            if not re.fullmatch(r'\.state-[A-Za-z0-9_-]{1,64}', entry.name):
                raise ValueError('unexpected budget entry')
            info = entry.stat(follow_symlinks=False)
            _private(info)
            if info.st_size > MAX_STATE_BYTES:
                raise ValueError('oversized temporary budget')
            temporary.append(entry.name)
    for name in temporary:
        os.unlink(name, dir_fd=directory_fd)


def _update(email=None, kind=None):
    root = Path(settings.AUTH_MAIL_BUDGET_DIR)
    today = datetime.now(timezone.utc).date()
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _private(os.fstat(directory_fd), directory=True)
            fd = os.open('.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                         0o600, dir_fd=directory_fd)
            with os.fdopen(fd, 'rb') as lock:
                _private(os.fstat(lock.fileno()))
                fcntl.flock(lock, fcntl.LOCK_EX)
                _purge_temporary_states(directory_fd)
                value = _read_state(directory_fd, today)
                if kind is not None:
                    digest = hmac.new(settings.SECRET_KEY.encode(),
                        f'auth-mail:v1:{today.isoformat()}:{email.strip().lower()}'.encode(),
                        hashlib.sha256).hexdigest()
                    used = value['recipients'].get(digest, 0)
                    limit = (settings.AUTH_MAIL_VERIFICATION_DAILY_LIMIT if kind == 'verification'
                             else settings.AUTH_MAIL_RESET_DAILY_LIMIT)
                    scope = None
                    if value[kind] >= limit:
                        scope = 'global'
                    elif used >= settings.AUTH_MAIL_RECIPIENT_DAILY_LIMIT:
                        scope = 'recipient'
                    elif digest not in value['recipients'] and len(value['recipients']) >= MAX_RECIPIENTS:
                        scope = 'global'
                    if scope:
                        security_log.warning('event=auth_mail_budget_blocked scope=%s kind=%s', scope, kind)
                        raise AuthMailLimited
                    value[kind] += 1
                    value['recipients'][digest] = used + 1
                _write_state(root, directory_fd, value)
        finally:
            os.close(directory_fd)
    except AuthMailLimited:
        raise
    except (OSError, ValueError, TypeError, OverflowError):
        security_log.error('event=auth_mail_budget_unavailable')
        raise AuthMailUnavailable from None


def reserve_auth_mail(email, kind):
    if kind not in {'verification', 'reset'}:
        raise ValueError('unknown auth mail kind')
    _update(email, kind)


def expire_auth_mail_budget():
    """Daily maintenance replaces prior-day hashes without sending any mail."""
    if Path(settings.AUTH_MAIL_BUDGET_DIR).exists():
        _update()


def check_auth_mail_budget():
    """Bootstrap/validate private state without reserving or sending email."""
    _update()
