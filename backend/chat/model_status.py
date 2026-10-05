"""Runtime availability of catalog models.

`manage.py probe_models` (systemd timer, weekly) probes every catalog model against the
live NVIDIA API and writes the result here as JSON. `/api/models/` subtracts
the unavailable set so dead models never reach the picker, without a deploy.

The file lives in the private runtime cache rather than deployable source: the
catalog says what we *support*, this file says what NVIDIA currently *serves*.
"""
import json
from pathlib import Path

from django.conf import settings


def _status_file() -> Path:
    return Path(getattr(settings, 'MODEL_STATUS_FILE', Path(settings.BASE_DIR) / '.cache/model_status.json'))


_cache = {'mtime': None, 'data': {}}


def get_status() -> dict:
    path = _status_file()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return {}
    if _cache['mtime'] != mtime:
        try:
            _cache['data'] = json.loads(path.read_text())
        except (ValueError, OSError):
            _cache['data'] = {}
        _cache['mtime'] = mtime
    return _cache['data'] or {}


def unavailable_model_ids() -> set:
    return set(get_status().get('unavailable', []))


def write_status(unavailable, checked_at, results=None):
    payload = {'checked_at': checked_at, 'unavailable': sorted(unavailable)}
    if results:
        payload['results'] = results
    path = _status_file()
    tmp = path.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(payload, indent=1))
    tmp.replace(path)
