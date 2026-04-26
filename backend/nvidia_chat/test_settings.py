"""Test settings: SQLite in-memory, in-process cache, tmp media, no external IO."""
import tempfile

from .settings import *  # noqa

DEBUG = False

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

# Avoid SMTP timeouts during tests
EMAIL_TIMEOUT = 1

# Fast password hasher for tests (10x speedup on auth tests).
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']

# Required env vars from settings.py — provide test stubs.
NVIDIA_API_KEY = 'test-nvidia-key'
