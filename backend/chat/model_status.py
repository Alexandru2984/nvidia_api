"""Runtime availability of catalog models.

`manage.py probe_models` (systemd timer, twice weekly) probes every catalog model
against the live NVIDIA API and writes the result here as JSON. `/api/models/`
subtracts the unavailable set so dead models never reach the picker, without a deploy.

The production file is owned by the isolated probe identity and signed with an
Ed25519 key unavailable to the web worker: the catalog says what we *support*,
this file says what NVIDIA currently *serves*.
"""
import base64
import binascii
import json
import logging
import os
import grp
import pwd
import stat
import tempfile
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_STATUS_FILE_BYTES = 512 * 1024
MAX_PROBE_LATENCY_MS = 120_000
MAX_INCONCLUSIVE_STREAK = 100
ALLOWED_OUTCOMES = {
    'available', 'retired', 'rejected', 'throttled', 'provider_error',
    'authorization_error', 'entitlement_error', 'timeout', 'network_error',
    'protocol_error',
}
TRANSIENT_OUTCOMES = frozenset({
    'throttled', 'provider_error', 'authorization_error',
    'entitlement_error', 'timeout', 'network_error', 'protocol_error',
})
MAX_CLOCK_SKEW = timedelta(minutes=5)
SIGNATURE_BYTES = 64
security_log = logging.getLogger('security')


def _status_file() -> Path:
    return Path(getattr(settings, 'MODEL_STATUS_FILE', Path(settings.BASE_DIR) / '.cache/model_status.json'))


def _fail_closed_status(state='invalid', checked_at=None) -> dict:
    from .models_catalog import MODEL_IDS
    result = {
        'unavailable': sorted(MODEL_IDS),
        'state': state,
        'inconclusive_models': 0,
        'unverified_models': 0,
    }
    if checked_at:
        result['checked_at'] = checked_at
    return result


_cache = {
    'path': None,
    'mtime_ns': None,
    'key_marker': None,
    'data': {},
    'reported_problem': None,
}


def _report_problem_once(path_key, marker, reason):
    problem = (path_key, marker, reason)
    if _cache['reported_problem'] == problem:
        return
    security_log.error('event=model_status_invalid reason=%s', reason)
    _cache['reported_problem'] = problem


def _canonical_status(value):
    return json.dumps(
        value, ensure_ascii=False, separators=(',', ':'), sort_keys=True,
    ).encode('utf-8')


def _load_regular_key(path, *, private=False):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError('key is not a regular file')
    if not 1 <= info.st_size <= 4096 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError('key permissions or size are unsafe')
    data = path.read_bytes()
    loader = (
        serialization.load_pem_private_key
        if private else serialization.load_pem_public_key
    )
    key = loader(data, password=None) if private else loader(data)
    expected = Ed25519PrivateKey if private else Ed25519PublicKey
    if not isinstance(key, expected):
        raise ValueError('key is not Ed25519')
    return key, (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_size)


def _public_key():
    path = getattr(settings, 'MODEL_STATUS_PUBLIC_KEY_FILE', '')
    if not path:
        raise ValueError('public key path is not configured')
    return _load_regular_key(path)


def _signature_required():
    return bool(getattr(settings, 'MODEL_STATUS_SIGNATURE_REQUIRED', False))


def _verify_signature(value):
    signature = value.get('signature') if isinstance(value, dict) else None
    if signature is None:
        return not _signature_required()
    if not isinstance(signature, str) or len(signature) != 88:
        return False
    try:
        decoded = base64.b64decode(
            signature.encode('ascii'), altchars=b'-_', validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError):
        return False
    if (
        len(decoded) != SIGNATURE_BYTES
        or base64.urlsafe_b64encode(decoded).decode('ascii') != signature
    ):
        return False
    unsigned = dict(value)
    del unsigned['signature']
    try:
        key, _ = _public_key()
        key.verify(decoded, _canonical_status(unsigned))
    except (InvalidSignature, OSError, TypeError, ValueError):
        return False
    return True


def _status_permissions_are_valid(info):
    if not getattr(settings, 'MODEL_STATUS_SECURE_PERMISSIONS_REQUIRED', False):
        return True
    try:
        owner = pwd.getpwnam(settings.MODEL_STATUS_EXPECTED_OWNER).pw_uid
        group = grp.getgrnam(settings.MODEL_STATUS_EXPECTED_GROUP).gr_gid
    except (KeyError, AttributeError):
        return False
    expected_mode = int(getattr(settings, 'MODEL_STATUS_EXPECTED_MODE', 0o640))
    return (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == owner
        and info.st_gid == group
        and stat.S_IMODE(info.st_mode) == expected_mode
    )


def _runtime_status(value, *, path_key, marker, now=None):
    """Apply time-sensitive trust rules to a schema-validated status."""
    if value.get('state') == 'invalid':
        return value

    checked_at = value.get('checked_at')
    parsed = parse_datetime(checked_at) if checked_at else None
    if parsed is None or not timezone.is_aware(parsed):
        _report_problem_once(path_key, marker, 'timestamp')
        return _fail_closed_status('invalid', checked_at)

    now = now or timezone.now()
    if parsed > now + MAX_CLOCK_SKEW:
        _report_problem_once(path_key, marker, 'future_timestamp')
        return _fail_closed_status('invalid', checked_at)
    if now - parsed > timedelta(seconds=settings.MODEL_STATUS_MAX_AGE_SECONDS):
        _report_problem_once(path_key, marker, 'stale')
        return _fail_closed_status('stale', checked_at)

    _cache['reported_problem'] = None
    from .models_catalog import MODEL_IDS

    results = value.get('results', {})
    unverified = MODEL_IDS - set(results)
    inconclusive = sum(
        result.get('outcome') in TRANSIENT_OUTCOMES
        for result in results.values()
        if isinstance(result, dict)
    )
    runtime = dict(value)
    runtime['unavailable'] = sorted(set(value['unavailable']) | unverified)
    runtime['state'] = 'degraded' if inconclusive or unverified else 'verified'
    runtime['inconclusive_models'] = inconclusive
    runtime['unverified_models'] = len(unverified)
    return runtime


def _validated_status(value) -> dict:
    """Return only bounded, catalog-scoped runtime status fields."""
    if not isinstance(value, dict) or not isinstance(value.get('unavailable'), list):
        security_log.error('event=model_status_invalid reason=schema')
        return _fail_closed_status()
    from .models_catalog import MODEL_IDS

    checked_at = value.get('checked_at')
    parsed_checked_at = parse_datetime(checked_at) if isinstance(checked_at, str) else None
    if (
        not isinstance(checked_at, str)
        or len(checked_at) > 64
        or parsed_checked_at is None
        or not timezone.is_aware(parsed_checked_at)
    ):
        security_log.error('event=model_status_invalid reason=timestamp')
        return _fail_closed_status()

    raw_unavailable = value.get('unavailable')
    unavailable = sorted({
        model_id for model_id in raw_unavailable
        if isinstance(model_id, str) and model_id in MODEL_IDS
    }) if isinstance(raw_unavailable, list) else []

    results = {}
    raw_results = value.get('results')
    if isinstance(raw_results, dict):
        for model_id, result in raw_results.items():
            if model_id not in MODEL_IDS or not isinstance(result, dict):
                continue
            outcome = result.get('outcome')
            latency_ms = result.get('latency_ms')
            attempts = result.get('attempts', 1)
            inconclusive_streak = result.get('inconclusive_streak')
            if outcome not in ALLOWED_OUTCOMES:
                continue
            if not isinstance(latency_ms, int) or isinstance(latency_ms, bool):
                continue
            if not 0 <= latency_ms <= MAX_PROBE_LATENCY_MS:
                continue
            if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts not in (1, 2):
                continue
            if inconclusive_streak is None:
                # Backward-compatible migration for runtime files written before
                # the bounded failure streak became part of the private schema.
                inconclusive_streak = 1 if outcome in TRANSIENT_OUTCOMES else 0
            if (
                not isinstance(inconclusive_streak, int)
                or isinstance(inconclusive_streak, bool)
                or not 0 <= inconclusive_streak <= MAX_INCONCLUSIVE_STREAK
            ):
                continue
            if outcome in TRANSIENT_OUTCOMES:
                if inconclusive_streak < 1:
                    continue
            elif inconclusive_streak != 0:
                continue
            results[model_id] = {
                'outcome': outcome,
                'latency_ms': latency_ms,
                'attempts': attempts,
                'inconclusive_streak': inconclusive_streak,
            }

    cleaned = {'unavailable': unavailable, 'checked_at': checked_at}
    if results:
        cleaned['results'] = results
    return cleaned


def get_status() -> dict:
    path = _status_file()
    path_key = str(path.resolve())
    try:
        file_info = path.lstat()
    except FileNotFoundError:
        if getattr(settings, 'MODEL_STATUS_REQUIRED', not settings.DEBUG):
            _report_problem_once(path_key, None, 'missing')
            return _fail_closed_status('missing')
        _cache['reported_problem'] = None
        from .models_catalog import MODEL_IDS
        return {
            'unavailable': [],
            'state': 'unverified',
            'inconclusive_models': 0,
            'unverified_models': len(MODEL_IDS),
        }
    except OSError:
        _report_problem_once(path_key, None, 'unreadable')
        return _fail_closed_status()
    if not stat.S_ISREG(file_info.st_mode) or stat.S_ISLNK(file_info.st_mode):
        _report_problem_once(path_key, None, 'not_regular')
        return _fail_closed_status()
    if not _status_permissions_are_valid(file_info):
        _report_problem_once(path_key, file_info.st_mtime_ns, 'permissions')
        return _fail_closed_status()
    if file_info.st_size > MAX_STATUS_FILE_BYTES:
        if _cache['path'] != path_key or _cache['mtime_ns'] != file_info.st_mtime_ns:
            security_log.error('event=model_status_invalid reason=oversized')
            _cache['path'] = path_key
            _cache['mtime_ns'] = file_info.st_mtime_ns
            _cache['data'] = _fail_closed_status()
        return _cache['data']
    try:
        _, key_marker = _public_key() if _signature_required() else (None, None)
    except (OSError, TypeError, ValueError):
        _report_problem_once(path_key, file_info.st_mtime_ns, 'public_key')
        return _fail_closed_status()
    if (
        _cache['path'] != path_key
        or _cache['mtime_ns'] != file_info.st_mtime_ns
        or _cache['key_marker'] != key_marker
    ):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if not _verify_signature(data):
                security_log.error('event=model_status_invalid reason=signature')
                _cache['data'] = _fail_closed_status()
            else:
                _cache['data'] = _validated_status(data)
        except (ValueError, OSError):
            security_log.error('event=model_status_invalid reason=unreadable')
            _cache['data'] = _fail_closed_status()
        _cache['path'] = path_key
        _cache['mtime_ns'] = file_info.st_mtime_ns
        _cache['key_marker'] = key_marker
    return _runtime_status(
        _cache['data'] or _fail_closed_status(),
        path_key=path_key,
        marker=file_info.st_mtime_ns,
    )


def unavailable_model_ids(runtime_status=None) -> set:
    return set((runtime_status or get_status()).get('unavailable', []))


def write_status(unavailable, checked_at, results=None):
    payload = {'checked_at': checked_at, 'unavailable': sorted(unavailable)}
    if results:
        payload['results'] = results
    payload = _validated_status(payload)
    private_key_path = getattr(settings, 'MODEL_STATUS_PRIVATE_KEY_FILE', '')
    if private_key_path:
        key, _ = _load_regular_key(private_key_path, private=True)
        signature = key.sign(_canonical_status(payload))
        payload['signature'] = base64.urlsafe_b64encode(signature).decode('ascii')
    elif _signature_required():
        raise ValueError('model-status signing key is required')
    path = _status_file()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', dir=path.parent,
            prefix=f'.{path.name}.', suffix='.tmp', delete=False,
        ) as temporary:
            temporary_name = temporary.name
            json.dump(payload, temporary, indent=1)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.chmod(
            temporary_name,
            int(getattr(settings, 'MODEL_STATUS_WRITE_MODE', 0o600)),
        )
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
