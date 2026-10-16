"""
Django settings for nvidia_chat project.
"""

import base64
import binascii
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

_runtime_dir_value = os.environ.get('AICHAT_RUNTIME_DIR')
if _runtime_dir_value:
    RUNTIME_DIR = Path(_runtime_dir_value)
    if not RUNTIME_DIR.is_absolute():
        raise ImproperlyConfigured('AICHAT_RUNTIME_DIR must be an absolute path.')
    RUNTIME_DIR = RUNTIME_DIR.resolve()
else:
    RUNTIME_DIR = BASE_DIR

# Production code is deployed below /opt while secrets and mutable state remain
# in the private application runtime directory. Local development keeps the
# historical single-directory layout.
load_dotenv(RUNTIME_DIR / '.env')

DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', '')
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = 'dev-only-insecure-key'
    else:
        raise ImproperlyConfigured('DJANGO_SECRET_KEY must be set when DEBUG is off.')
ALLOWED_HOSTS = [h.strip() for h in os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',') if h.strip()]


_KEY_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')


def _keyring_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key identifier')
        result[key] = value
    return result


def _load_keyring(keys_name, active_name, development_domain):
    raw = os.environ.get(keys_name, '').strip()
    active = os.environ.get(active_name, '').strip()
    if not raw:
        if not DEBUG:
            raise ImproperlyConfigured(f'{keys_name} must be set when DEBUG is off.')
        # Development-only convenience. Production must always supply an
        # independently generated root key so rotating Django signing material
        # cannot make TOTP or recovery artifacts unusable.
        derived = hashlib.sha256(
            development_domain + b'\0' + SECRET_KEY.encode('utf-8'),
        ).digest()
        return {'development': base64.urlsafe_b64encode(derived).decode('ascii')}, 'development'
    try:
        parsed = json.loads(raw, object_pairs_hook=_keyring_json_object)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ImproperlyConfigured(f'{keys_name} must be a valid JSON object.') from exc
    if not isinstance(parsed, dict) or not 1 <= len(parsed) <= 8:
        raise ImproperlyConfigured(f'{keys_name} must contain between 1 and 8 keys.')
    for key_id, encoded in parsed.items():
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise ImproperlyConfigured(f'{keys_name} contains an invalid key identifier.')
        if not isinstance(encoded, str) or len(encoded) != 44:
            raise ImproperlyConfigured(f'Every {keys_name} value must be a base64url key.')
        try:
            decoded = base64.b64decode(encoded.encode('ascii'), altchars=b'-_', validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise ImproperlyConfigured(f'Every {keys_name} value must be a base64url key.') from exc
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode('ascii') != encoded:
            raise ImproperlyConfigured(f'Every {keys_name} value must encode exactly 32 bytes.')
    if not active or active not in parsed:
        raise ImproperlyConfigured(f'{active_name} must select a configured key.')
    return parsed, active


def _legacy_key_compatibility(name):
    raw = os.environ.get(name, str(DEBUG)).strip().lower()
    if raw not in {'true', 'false'}:
        raise ImproperlyConfigured(f'{name} must be true or false.')
    return raw == 'true'


TWO_FACTOR_KEYS, TWO_FACTOR_ACTIVE_KEY_ID = _load_keyring(
    'TWO_FACTOR_KEYS',
    'TWO_FACTOR_ACTIVE_KEY_ID',
    b'aichat-development-two-factor-key',
)
TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED = (
    _legacy_key_compatibility('TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED')
)
ADMIN_AUDIT_KEYS, ADMIN_AUDIT_ACTIVE_KEY_ID = _load_keyring(
    'ADMIN_AUDIT_KEYS',
    'ADMIN_AUDIT_ACTIVE_KEY_ID',
    b'aichat-development-admin-audit-key',
)
ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED = (
    _legacy_key_compatibility('ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED')
)

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.postgres',
    'rest_framework',
    'corsheaders',
    'chat',
]

MIDDLEWARE = [
    'chat.middleware.RealClientIPMiddleware',
    'chat.middleware.PrivateAPIResponseMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'chat.middleware.AbsoluteSessionMiddleware',
    'chat.middleware.StaffAdminTwoFactorMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'nvidia_chat.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'nvidia_chat.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ['DB_NAME'],
        'USER': os.environ['DB_USER'],
        'PASSWORD': os.environ['DB_PASSWORD'],
        'HOST': os.environ.get('DB_HOST', '127.0.0.1'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = RUNTIME_DIR / 'staticfiles'

MEDIA_URL = '/media/'
MEDIA_ROOT = RUNTIME_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024
MAX_USER_STORAGE = 100 * 1024 * 1024
ATTACHMENT_TTL_DAYS = 30
DOC_EXTRACT_MAX_CHARS = 50_000
ATTACHMENT_PREVIEW_MAX_CHARS = 4_000

ALLOWED_IMAGE_MIMES = {'image/jpeg', 'image/png', 'image/webp', 'image/gif'}
ALLOWED_DOC_MIMES = {
    'application/pdf',
    'text/plain',
    'text/markdown',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
}
ALLOWED_UPLOAD_MIMES = ALLOWED_IMAGE_MIMES | ALLOWED_DOC_MIMES

CORS_ALLOWED_ORIGINS = [
    'https://aichat.micutu.com',
]
CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    'https://aichat.micutu.com',
]
if DEBUG:
    CSRF_TRUSTED_ORIGINS += ['http://localhost:5173', 'http://127.0.0.1:5173']

SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False  # frontend reads csrftoken cookie to set X-CSRFToken header
SESSION_COOKIE_AGE = 14 * 24 * 60 * 60  # 2 weeks; default is 2 years
SESSION_SAVE_EVERY_REQUEST = True  # sliding expiration — active users stay logged in

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
if not DEBUG:
    SECURE_HSTS_SECONDS = 60 * 60 * 24 * 365
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = False
    # Defense in depth behind nginx/Cloudflare. SECURE_PROXY_SSL_HEADER below
    # prevents a redirect loop for requests that arrived over HTTPS.
    SECURE_SSL_REDIRECT = True

RATELIMIT_ENABLE = not DEBUG

# Shared cache so ratelimit buckets are global across the 3 gunicorn workers
# (default LocMemCache is per-process, which silently triples the effective rate).
# Lives under RUNTIME_DIR, not /tmp: survives reboots and isn't subject to
# systemd PrivateTmp giving cron and gunicorn different /tmp namespaces.
CACHES = {
    'default': {
        'BACKEND': 'chat.cache.AtomicFileCache',
        'LOCATION': str(RUNTIME_DIR / '.cache'),
        'TIMEOUT': 60 * 60,
        'OPTIONS': {'MAX_ENTRIES': 10000},
    },
}

# Mutable provider availability belongs with the private runtime cache rather
# than alongside deployable source. The dedicated service identity owns it.
MODEL_STATUS_FILE = RUNTIME_DIR / '.cache' / 'model_status.json'

CHAT_MAX_MESSAGE_CHARS = 8000
CHAT_HISTORY_MAX_MESSAGES = 30
CHAT_HISTORY_MAX_CHARS = 25_000
CHAT_MAX_ATTACHMENTS_PER_MESSAGE = 8
CHAT_MAX_ATTACHMENT_BYTES_PER_MESSAGE = 20 * 1024 * 1024
CHAT_MAX_DOCUMENT_CHARS_PER_MESSAGE = 50_000
CHAT_HISTORY_MAX_IMAGE_BYTES = 20 * 1024 * 1024

MAX_PASSWORD_LENGTH = 128

REGISTRATION_MODE = os.environ.get('REGISTRATION_MODE', 'open').strip().lower()
if REGISTRATION_MODE not in {'open', 'invite', 'closed'}:
    raise ImproperlyConfigured('REGISTRATION_MODE must be open, invite, or closed.')


def _nonnegative_int_env(name, default):
    value = int(os.environ.get(name, default))
    if value < 0:
        raise ValueError(f'{name} must be non-negative')
    return value


def _boolean_env(name, default):
    value = os.environ.get(name, str(default)).strip().lower()
    if value not in {'true', 'false'}:
        raise ImproperlyConfigured(f'{name} must be true or false.')
    return value == 'true'


ATTACHMENT_MALWARE_SCAN_REQUIRED = _boolean_env(
    'ATTACHMENT_MALWARE_SCAN_REQUIRED', not DEBUG,
)
ATTACHMENT_SCANNER_SOCKET = os.environ.get(
    'ATTACHMENT_SCANNER_SOCKET', '/run/clamav/clamd.ctl',
).strip()
ATTACHMENT_SCAN_TIMEOUT_SECONDS = _nonnegative_int_env(
    'ATTACHMENT_SCAN_TIMEOUT_SECONDS', 20,
)
if ATTACHMENT_MALWARE_SCAN_REQUIRED and not Path(ATTACHMENT_SCANNER_SOCKET).is_absolute():
    raise ImproperlyConfigured('ATTACHMENT_SCANNER_SOCKET must be an absolute path.')
if not 1 <= ATTACHMENT_SCAN_TIMEOUT_SECONDS <= 60:
    raise ImproperlyConfigured('ATTACHMENT_SCAN_TIMEOUT_SECONDS must be between 1 and 60.')

DOCUMENT_PARSER_REQUIRED = _boolean_env(
    'DOCUMENT_PARSER_REQUIRED', not DEBUG,
)
DOCUMENT_PARSER_SOCKET = os.environ.get(
    'DOCUMENT_PARSER_SOCKET', '/run/aichat-document-parser/parser.sock',
).strip()
DOCUMENT_PARSER_TIMEOUT_SECONDS = _nonnegative_int_env(
    'DOCUMENT_PARSER_TIMEOUT_SECONDS', 10,
)
if DOCUMENT_PARSER_REQUIRED and not Path(DOCUMENT_PARSER_SOCKET).is_absolute():
    raise ImproperlyConfigured('DOCUMENT_PARSER_SOCKET must be an absolute path.')
if not 1 <= DOCUMENT_PARSER_TIMEOUT_SECONDS <= 30:
    raise ImproperlyConfigured('DOCUMENT_PARSER_TIMEOUT_SECONDS must be between 1 and 30.')


SESSION_ABSOLUTE_MAX_AGE_SECONDS = _nonnegative_int_env(
    'SESSION_ABSOLUTE_MAX_AGE_SECONDS', 30 * 24 * 60 * 60,
)
SESSION_MAX_ACTIVE_PER_USER = _nonnegative_int_env(
    'SESSION_MAX_ACTIVE_PER_USER', 20,
)
RECENT_AUTH_MAX_AGE_SECONDS = _nonnegative_int_env(
    'RECENT_AUTH_MAX_AGE_SECONDS', 5 * 60,
)
if not 60 * 60 <= SESSION_ABSOLUTE_MAX_AGE_SECONDS <= 365 * 24 * 60 * 60:
    raise ImproperlyConfigured(
        'SESSION_ABSOLUTE_MAX_AGE_SECONDS must be between 3600 and 31536000.',
    )
if not 1 <= SESSION_MAX_ACTIVE_PER_USER <= 100:
    raise ImproperlyConfigured('SESSION_MAX_ACTIVE_PER_USER must be between 1 and 100.')
if not 60 <= RECENT_AUTH_MAX_AGE_SECONDS <= 60 * 60:
    raise ImproperlyConfigured(
        'RECENT_AUTH_MAX_AGE_SECONDS must be between 60 and 3600.',
    )


REGISTRATION_INVITE_AUDIT_DAYS = _nonnegative_int_env('REGISTRATION_INVITE_AUDIT_DAYS', 90)
ADMIN_AUDIT_RETENTION_DAYS = _nonnegative_int_env('ADMIN_AUDIT_RETENTION_DAYS', 365)
ATTACHMENT_UPLOAD_ATTEMPT_TTL_HOURS = _nonnegative_int_env(
    'ATTACHMENT_UPLOAD_ATTEMPT_TTL_HOURS', 24,
)
MODEL_STATUS_REQUIRED = os.environ.get(
    'MODEL_STATUS_REQUIRED', str(not DEBUG),
).lower() == 'true'
MODEL_STATUS_MAX_AGE_SECONDS = _nonnegative_int_env(
    'MODEL_STATUS_MAX_AGE_SECONDS', 8 * 24 * 60 * 60,
)
if MODEL_STATUS_MAX_AGE_SECONDS < 60 * 60:
    raise ImproperlyConfigured('MODEL_STATUS_MAX_AGE_SECONDS must be at least 3600.')

CHAT_GENERATION_LEASE_SECONDS = _nonnegative_int_env(
    'CHAT_GENERATION_LEASE_SECONDS', 15 * 60,
)
if not 300 <= CHAT_GENERATION_LEASE_SECONDS <= 60 * 60:
    raise ImproperlyConfigured(
        'CHAT_GENERATION_LEASE_SECONDS must be between 300 and 3600.',
    )
GENERATION_REQUEST_RETENTION_DAYS = _nonnegative_int_env(
    'GENERATION_REQUEST_RETENTION_DAYS', 7,
)
if not 1 <= GENERATION_REQUEST_RETENTION_DAYS <= 90:
    raise ImproperlyConfigured(
        'GENERATION_REQUEST_RETENTION_DAYS must be between 1 and 90.',
    )

CHAT_MAX_CONVERSATIONS_PER_USER = _nonnegative_int_env(
    'CHAT_MAX_CONVERSATIONS_PER_USER', 500,
)
CHAT_MAX_MESSAGES_PER_USER = _nonnegative_int_env(
    'CHAT_MAX_MESSAGES_PER_USER', 10_000,
)
CHAT_MAX_MESSAGES_PER_CONVERSATION = _nonnegative_int_env(
    'CHAT_MAX_MESSAGES_PER_CONVERSATION', 2_000,
)
CHAT_MAX_ASSISTANT_CHARS = _nonnegative_int_env(
    'CHAT_MAX_ASSISTANT_CHARS', 64_000,
)
CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION = _nonnegative_int_env(
    'CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION', 16 * 1024 * 1024,
)
CHAT_MAX_MESSAGE_BYTES_PER_USER = _nonnegative_int_env(
    'CHAT_MAX_MESSAGE_BYTES_PER_USER', 64 * 1024 * 1024,
)
CHAT_MAX_MESSAGE_BYTES_GLOBAL = _nonnegative_int_env(
    'CHAT_MAX_MESSAGE_BYTES_GLOBAL', 1024 * 1024 * 1024,
)
CHAT_MAX_EXPORT_BYTES = _nonnegative_int_env(
    'CHAT_MAX_EXPORT_BYTES', 25 * 1024 * 1024,
)
if CHAT_MAX_CONVERSATIONS_PER_USER < 1:
    raise ImproperlyConfigured('CHAT_MAX_CONVERSATIONS_PER_USER must be positive.')
if CHAT_MAX_MESSAGES_PER_USER < 2:
    raise ImproperlyConfigured('CHAT_MAX_MESSAGES_PER_USER must be at least 2.')
if not 2 <= CHAT_MAX_MESSAGES_PER_CONVERSATION <= CHAT_MAX_MESSAGES_PER_USER:
    raise ImproperlyConfigured(
        'CHAT_MAX_MESSAGES_PER_CONVERSATION must be between 2 and the per-user limit.',
    )
if CHAT_MAX_ASSISTANT_CHARS < CHAT_MAX_MESSAGE_CHARS:
    raise ImproperlyConfigured(
        'CHAT_MAX_ASSISTANT_CHARS must be at least CHAT_MAX_MESSAGE_CHARS.',
    )
minimum_exchange_bytes = 4 * (CHAT_MAX_MESSAGE_CHARS + CHAT_MAX_ASSISTANT_CHARS)
if CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION < minimum_exchange_bytes:
    raise ImproperlyConfigured(
        'CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION must fit one maximum UTF-8 exchange.',
    )
if not (
    CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION
    <= CHAT_MAX_MESSAGE_BYTES_PER_USER
    <= CHAT_MAX_MESSAGE_BYTES_GLOBAL
):
    raise ImproperlyConfigured(
        'Chat message byte limits must be ordered conversation <= user <= global.',
    )
if CHAT_MAX_EXPORT_BYTES < 1024 * 1024:
    raise ImproperlyConfigured('CHAT_MAX_EXPORT_BYTES must be at least 1 MiB.')


# Durable daily provider budgets. Set AI_GENERATION_ENABLED=False and restart
# the service for an immediate global cost/abuse circuit breaker.
AI_GENERATION_ENABLED = os.environ.get('AI_GENERATION_ENABLED', 'True').lower() == 'true'
AI_USER_DAILY_CHAT_LIMIT = _nonnegative_int_env('AI_USER_DAILY_CHAT_LIMIT', 100)
AI_USER_DAILY_IMAGE_LIMIT = _nonnegative_int_env('AI_USER_DAILY_IMAGE_LIMIT', 10)
AI_GLOBAL_DAILY_CHAT_LIMIT = _nonnegative_int_env('AI_GLOBAL_DAILY_CHAT_LIMIT', 500)
AI_GLOBAL_DAILY_IMAGE_LIMIT = _nonnegative_int_env('AI_GLOBAL_DAILY_IMAGE_LIMIT', 50)
AI_USER_DAILY_TOKEN_LIMIT = _nonnegative_int_env('AI_USER_DAILY_TOKEN_LIMIT', 500_000)
AI_GLOBAL_DAILY_TOKEN_LIMIT = _nonnegative_int_env('AI_GLOBAL_DAILY_TOKEN_LIMIT', 2_500_000)
# Reserved atomically before each streamed request, then replaced with the
# provider's actual usage. A missing usage chunk stays reserved (fail closed).
AI_CHAT_TOKEN_RESERVATION = _nonnegative_int_env('AI_CHAT_TOKEN_RESERVATION', 32_768)

DATA_UPLOAD_MAX_MEMORY_SIZE = 12 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 12 * 1024 * 1024
DATA_UPLOAD_MAX_NUMBER_FIELDS = 200

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {'format': '[%(asctime)s] %(levelname)s %(name)s: %(message)s'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'simple'},
    },
    'root': {'handlers': ['console'], 'level': 'INFO'},
    'loggers': {
        'django.request': {'level': 'WARNING', 'propagate': True},
        'chat': {'level': 'INFO', 'propagate': True},
        'security': {'handlers': ['console'], 'level': 'INFO', 'propagate': False},
    },
}

REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer'],
    'DEFAULT_PARSER_CLASSES': ['chat.security.ObjectJSONParser'],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'chat.security.CSRFSafeSessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}

def _nvidia_endpoint(name, default, hostname, path):
    value = os.environ.get(name, default).strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        parsed = None
        port = None
    valid = (
        parsed is not None
        and parsed.scheme == 'https'
        and parsed.netloc in {hostname, f'{hostname}:443'}
        and parsed.hostname == hostname
        and port in (None, 443)
        and parsed.username is None
        and parsed.password is None
        and parsed.path == path
        and not parsed.query
        and not parsed.fragment
    )
    if not valid:
        raise ImproperlyConfigured(
            f'{name} must be the approved NVIDIA HTTPS endpoint {hostname}{path}.',
        )
    return value


NVIDIA_API_KEY = os.environ['NVIDIA_API_KEY']
NVIDIA_API_URL = _nvidia_endpoint(
    'NVIDIA_API_URL',
    'https://integrate.api.nvidia.com/v1/chat/completions',
    'integrate.api.nvidia.com',
    '/v1/chat/completions',
)
NVIDIA_GENAI_BASE = _nvidia_endpoint(
    'NVIDIA_GENAI_BASE',
    'https://ai.api.nvidia.com/v1/genai',
    'ai.api.nvidia.com',
    '/v1/genai',
)
NVIDIA_GENAI_STATUS_BASE = _nvidia_endpoint(
    'NVIDIA_GENAI_STATUS_BASE',
    'https://ai.api.nvidia.com/v1/status',
    'ai.api.nvidia.com',
    '/v1/status',
)

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ.get('SMTP_HOST', 'localhost')
EMAIL_PORT = int(os.environ.get('SMTP_PORT', '465'))
EMAIL_HOST_USER = os.environ.get('SMTP_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('SMTP_PASS', '')
EMAIL_USE_SSL = EMAIL_PORT == 465
EMAIL_USE_TLS = not EMAIL_USE_SSL
EMAIL_TIMEOUT = 15
DEFAULT_FROM_EMAIL = os.environ.get('SMTP_FROM', EMAIL_HOST_USER or 'noreply@example.com')

FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://aichat.micutu.com')
EMAIL_VERIFICATION_TTL_SECONDS = 60 * 60 * 24 * 2  # 2 days
