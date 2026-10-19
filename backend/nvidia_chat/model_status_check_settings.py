"""Credential-free settings for independent model-status verification."""
from pathlib import Path


SECRET_KEY = 'model-status-check-does-not-sign-django-data'
INSTALLED_APPS = []
USE_TZ = True
TIME_ZONE = 'UTC'
DEFAULT_CHARSET = 'utf-8'

MODEL_STATUS_FILE = Path('/var/lib/aichat-model-probe/model_status.json')
MODEL_STATUS_REQUIRED = True
MODEL_STATUS_MAX_AGE_SECONDS = 8 * 24 * 60 * 60
MODEL_STATUS_SIGNATURE_REQUIRED = True
MODEL_STATUS_SECURE_PERMISSIONS_REQUIRED = True
MODEL_STATUS_PUBLIC_KEY_FILE = '/etc/aichat/model-status-public.pem'
MODEL_STATUS_PRIVATE_KEY_FILE = ''
MODEL_STATUS_EXPECTED_OWNER = 'aichat-model-probe'
MODEL_STATUS_EXPECTED_GROUP = 'aichat'
MODEL_STATUS_EXPECTED_MODE = 0o640

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {'console': {'class': 'logging.StreamHandler'}},
    'loggers': {
        'security': {'handlers': ['console'], 'level': 'INFO', 'propagate': False},
    },
}
