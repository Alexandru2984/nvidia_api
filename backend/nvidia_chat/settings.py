"""
Django settings for nvidia_chat project.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', '')
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = 'dev-only-insecure-key'
    else:
        raise ImproperlyConfigured('DJANGO_SECRET_KEY must be set when DEBUG is off.')
ALLOWED_HOSTS = [h.strip() for h in os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',') if h.strip()]

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
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
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024
MAX_USER_STORAGE = 100 * 1024 * 1024
ATTACHMENT_TTL_DAYS = 30
DOC_EXTRACT_MAX_CHARS = 50_000

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
# Lives under BASE_DIR, not /tmp: survives reboots and isn't subject to
# systemd PrivateTmp giving cron and gunicorn different /tmp namespaces.
CACHES = {
    'default': {
        'BACKEND': 'chat.cache.AtomicFileCache',
        'LOCATION': str(BASE_DIR / '.cache'),
        'TIMEOUT': 60 * 60,
        'OPTIONS': {'MAX_ENTRIES': 10000},
    },
}

# Mutable provider availability belongs with the private runtime cache rather
# than alongside deployable source. The dedicated service identity owns it.
MODEL_STATUS_FILE = BASE_DIR / '.cache' / 'model_status.json'

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


REGISTRATION_INVITE_AUDIT_DAYS = _nonnegative_int_env('REGISTRATION_INVITE_AUDIT_DAYS', 90)


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

NVIDIA_API_KEY = os.environ['NVIDIA_API_KEY']
NVIDIA_API_URL = os.environ.get('NVIDIA_API_URL', 'https://integrate.api.nvidia.com/v1/chat/completions')
NVIDIA_GENAI_BASE = os.environ.get('NVIDIA_GENAI_BASE', 'https://ai.api.nvidia.com/v1/genai')
NVIDIA_GENAI_STATUS_BASE = os.environ.get('NVIDIA_GENAI_STATUS_BASE', 'https://ai.api.nvidia.com/v1/status')

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
