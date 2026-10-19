"""Minimal settings for the isolated NVIDIA model-availability probe.

The probe deliberately does not load the application dotenv, database, mail,
session, audit, or 2FA configuration. systemd supplies only the NVIDIA API key
and the model-status signing key through its private credential mount.
"""
import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured


def _credential(name, *, text=True):
    directory = os.environ.get('CREDENTIALS_DIRECTORY', '')
    if not directory or not Path(directory).is_absolute():
        raise ImproperlyConfigured('The systemd credential directory is unavailable.')
    path = Path(directory) / name
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ImproperlyConfigured(f'The {name} credential is unavailable.') from exc
    if not 1 <= len(data) <= 4096:
        raise ImproperlyConfigured(f'The {name} credential has an invalid size.')
    if not text:
        return str(path)
    try:
        value = data.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ImproperlyConfigured(f'The {name} credential is not UTF-8.') from exc
    if value.endswith('\n'):
        value = value[:-1]
    if not value or '\n' in value or '\r' in value or '\x00' in value:
        raise ImproperlyConfigured(f'The {name} credential is malformed.')
    return value


SECRET_KEY = 'isolated-probe-does-not-sign-django-data'
INSTALLED_APPS = []
USE_TZ = True
TIME_ZONE = 'UTC'
DEFAULT_CHARSET = 'utf-8'

NVIDIA_API_KEY = _credential('nvidia-api-key')
NVIDIA_API_URL = 'https://integrate.api.nvidia.com/v1/chat/completions'

MODEL_STATUS_FILE = Path('/var/lib/aichat-model-probe/model_status.json')
MODEL_STATUS_REQUIRED = False
MODEL_STATUS_MAX_AGE_SECONDS = 8 * 24 * 60 * 60
MODEL_STATUS_SIGNATURE_REQUIRED = True
MODEL_STATUS_SECURE_PERMISSIONS_REQUIRED = True
MODEL_STATUS_PUBLIC_KEY_FILE = '/etc/aichat/model-status-public.pem'
MODEL_STATUS_PRIVATE_KEY_FILE = _credential('model-status-private-key', text=False)
MODEL_STATUS_EXPECTED_OWNER = 'aichat-model-probe'
MODEL_STATUS_EXPECTED_GROUP = 'aichat'
MODEL_STATUS_EXPECTED_MODE = 0o640
MODEL_STATUS_WRITE_MODE = 0o640

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {'format': '[%(asctime)s] %(levelname)s %(name)s: %(message)s'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'simple'},
    },
    'loggers': {
        'security': {'handlers': ['console'], 'level': 'INFO', 'propagate': False},
    },
}
