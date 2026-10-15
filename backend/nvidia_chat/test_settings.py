"""Test settings: SQLite in-memory, in-process cache, tmp media, no external IO."""
import base64
import tempfile

from .settings import *

DEBUG = False
SECURE_SSL_REDIRECT = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'tests',
    },
}

# django-ratelimit honours this; tests that want to exercise the limiter
# override per-test with @override_settings(RATELIMIT_ENABLE=True).
RATELIMIT_ENABLE = False

# Don't write uploads under prod media dir.
MEDIA_ROOT = tempfile.mkdtemp(prefix='nvidia_test_media_')

# locmem mail backend so _send_*_email() doesn't hit SMTP.
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

# Predictable for HMAC tests. Don't reuse this anywhere.
SECRET_KEY = 'test-secret-key-do-not-use-in-prod'
TWO_FACTOR_KEYS = {
    'test-v1': base64.urlsafe_b64encode(b'\x01' * 32).decode('ascii'),
    'test-v2': base64.urlsafe_b64encode(b'\x02' * 32).decode('ascii'),
}
TWO_FACTOR_ACTIVE_KEY_ID = 'test-v1'
TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED = True
REGISTRATION_MODE = 'open'

# Avoid SMTP timeouts during tests
EMAIL_TIMEOUT = 1

# Fast password hasher for tests (10x speedup on auth tests).
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']

# Required env vars from settings.py — provide test stubs.
NVIDIA_API_KEY = 'test-nvidia-key'

# Keep tests away from the real model_status.json the weekly cron writes.
MODEL_STATUS_FILE = tempfile.gettempdir() + '/nvidia_test_model_status_does_not_exist.json'
MODEL_STATUS_REQUIRED = False
ATTACHMENT_MALWARE_SCAN_REQUIRED = False
DOCUMENT_PARSER_REQUIRED = False
