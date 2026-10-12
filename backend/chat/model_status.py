"""Runtime availability of catalog models.

`manage.py probe_models` (systemd timer, weekly) probes every catalog model against the
live NVIDIA API and writes the result here as JSON. `/api/models/` subtracts
the unavailable set so dead models never reach the picker, without a deploy.

The file lives in the private runtime cache rather than deployable source: the
catalog says what we *support*, this file says what NVIDIA currently *serves*.
"""
import json
import logging
import os
import tempfile
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

MAX_STATUS_FILE_BYTES = 512 * 1024
MAX_PROBE_LATENCY_MS = 120_000
ALLOWED_OUTCOMES = {
    'available', 'retired', 'rejected', 'throttled', 'provider_error',
    'authorization_error', 'entitlement_error', 'timeout', 'network_error',
}
TRANSIENT_OUTCOMES = frozenset({
    'throttled', 'provider_error', 'authorization_error',
    'entitlement_error', 'timeout', 'network_error',
})
MAX_CLOCK_SKEW = timedelta(minutes=5)
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


_cache = {'path': None, 'mtime_ns': None, 'data': {}, 'reported_problem': None}


def _report_problem_once(path_key, marker, reason):
    problem = (path_key, marker, reason)
    if _cache['reported_problem'] == problem:
        return
    security_log.error('event=model_status_invalid reason=%s', reason)
    _cache['reported_problem'] = problem


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
            if outcome not in ALLOWED_OUTCOMES:
                continue
            if not isinstance(latency_ms, int) or isinstance(latency_ms, bool):
                continue
            if not 0 <= latency_ms <= MAX_PROBE_LATENCY_MS:
                continue
            if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts not in (1, 2):
                continue
            results[model_id] = {
                'outcome': outcome,
                'latency_ms': latency_ms,
                'attempts': attempts,
            }

    cleaned = {'unavailable': unavailable, 'checked_at': checked_at}
    if results:
        cleaned['results'] = results
    return cleaned


def get_status() -> dict:
    path = _status_file()
    path_key = str(path.resolve())
    try:
        stat = path.stat()
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
    if stat.st_size > MAX_STATUS_FILE_BYTES:
        if _cache['path'] != path_key or _cache['mtime_ns'] != stat.st_mtime_ns:
            security_log.error('event=model_status_invalid reason=oversized')
            _cache['path'] = path_key
            _cache['mtime_ns'] = stat.st_mtime_ns
            _cache['data'] = _fail_closed_status()
        return _cache['data']
    if _cache['path'] != path_key or _cache['mtime_ns'] != stat.st_mtime_ns:
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            _cache['data'] = _validated_status(data)
        except (ValueError, OSError):
            security_log.error('event=model_status_invalid reason=unreadable')
            _cache['data'] = _fail_closed_status()
        _cache['path'] = path_key
        _cache['mtime_ns'] = stat.st_mtime_ns
    return _runtime_status(
        _cache['data'] or _fail_closed_status(),
        path_key=path_key,
        marker=stat.st_mtime_ns,
    )


def unavailable_model_ids(runtime_status=None) -> set:
    return set((runtime_status or get_status()).get('unavailable', []))


def write_status(unavailable, checked_at, results=None):
    payload = {'checked_at': checked_at, 'unavailable': sorted(unavailable)}
    if results:
        payload['results'] = results
    payload = _validated_status(payload)
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
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            Path(temporary_name).unlink(missing_ok=True)
