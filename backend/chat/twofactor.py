"""TOTP-based 2FA: enroll, verify, disable, and login plug-in.

Hardening notes:
- The TOTP secret is Fernet-encrypted at rest with a SECRET_KEY-derived key.
- Recovery code consumption runs inside select_for_update so two concurrent
  logins with the same code can't both succeed.
- Replay protection: every accepted TOTP code marks its 30-second step on the
  TwoFactor row; future requests with the same step are rejected even if the
  code itself is still inside the validity window.
- Per-account brute-force lockout: 5 failures → 10-minute lock on the TOTP
  factor (recovery codes still honoured so users can recover).
"""
import base64
import hashlib
import hmac
import io
import logging
import secrets
import time
from datetime import timedelta

import pyotp
import qrcode
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import transaction
from django.utils import timezone
from django_ratelimit.decorators import ratelimit
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import TwoFactor

log = logging.getLogger(__name__)

ISSUER = 'NVIDIA Chat Hub'
RECOVERY_CODE_COUNT = 10
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = timedelta(minutes=10)
TOTP_STEP_SECONDS = 30
TOTP_VALID_WINDOW = 1  # accept current step ± 1


def _fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode('utf-8')).digest())
    return Fernet(key)


def _encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode('utf-8')).decode('utf-8')


def _decrypt_secret(stored: str) -> str:
    """Decrypt the stored secret. Treat anything that isn't a valid Fernet token
    as a legacy plaintext base32 secret (for older rows pre-migration)."""
    try:
        return _fernet().decrypt(stored.encode('utf-8')).decode('utf-8')
    except (InvalidToken, ValueError):
        return stored


def _hash_recovery(code: str) -> str:
    pepper = settings.SECRET_KEY.encode()
    norm = code.strip().lower().replace('-', '').replace(' ', '')
    return hmac.new(pepper, norm.encode(), hashlib.sha256).hexdigest()


def _new_recovery_codes(n=RECOVERY_CODE_COUNT):
    plaintexts = []
    hashes = []
    for _ in range(n):
        raw = secrets.token_hex(4) + '-' + secrets.token_hex(4)
        plaintexts.append(raw)
        hashes.append(_hash_recovery(raw))
    return plaintexts, hashes


def _qr_data_url(provisioning_uri: str) -> str:
    from qrcode.image.svg import SvgImage
    img = qrcode.make(provisioning_uri, image_factory=SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return 'data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue()).decode()


def _verify_totp(secret_plain: str, code: str, last_step: int):
    """Return matched step (int) or None. Rejects replays of `last_step`."""
    if not (code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret_plain)
    current = int(time.time()) // TOTP_STEP_SECONDS
    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        step = current + offset
        if hmac.compare_digest(totp.at(step * TOTP_STEP_SECONDS), code):
            if step <= last_step:
                return None  # replay
            return step
    return None


def _record_failure(tf):
    """Bump failure count; lock the factor once the threshold is hit."""
    tf.failed_attempts = (tf.failed_attempts or 0) + 1
    if tf.failed_attempts >= LOCKOUT_THRESHOLD:
        tf.locked_until = timezone.now() + LOCKOUT_DURATION
    tf.save(update_fields=['failed_attempts', 'locked_until'])


def verify_for_login(user, code: str) -> bool:
    """True if `code` is a valid TOTP or unused recovery code for `user`.
    Recovery codes are consumed atomically; TOTP replays are rejected."""
    code = (code or '').strip()
    if not code:
        return False

    with transaction.atomic():
        # Lock the row so concurrent logins serialise (prevents recovery race
        # and concurrent TOTP-step bumps).
        tf = (TwoFactor.objects
              .select_for_update()
              .filter(user=user, enabled=True)
              .first())
        if tf is None:
            return True  # 2FA not configured — nothing to verify

        # Locked? Reject without burning the failure counter further.
        if tf.locked_until and tf.locked_until > timezone.now():
            return False

        plain = _decrypt_secret(tf.secret)

        # TOTP path
        matched = _verify_totp(plain, code, tf.last_totp_step)
        if matched is not None:
            tf.last_totp_step = matched
            tf.last_used_at = timezone.now()
            tf.failed_attempts = 0
            tf.locked_until = None
            tf.save(update_fields=['last_totp_step', 'last_used_at', 'failed_attempts', 'locked_until'])
            return True

        # Recovery code path
        h = _hash_recovery(code)
        if h in (tf.recovery_codes or []):
            tf.recovery_codes = [x for x in tf.recovery_codes if x != h]
            tf.last_used_at = timezone.now()
            tf.failed_attempts = 0
            tf.locked_until = None
            tf.save(update_fields=['recovery_codes', 'last_used_at', 'failed_attempts', 'locked_until'])
            log.info('2FA recovery code consumed for user_id=%s; %d remaining',
                     user.pk, len(tf.recovery_codes))
            return True

        _record_failure(tf)
        return False


def login_requires_2fa(user) -> bool:
    return TwoFactor.objects.filter(user=user, enabled=True).exists()


def _revoke_user_sessions(user, except_key=None):
    """Sign the user out everywhere (optionally keeping one session). Used on
    sensitive auth changes — disable 2FA, regen recovery codes, password reset."""
    from .sessions import _user_sessions
    deleted = 0
    for s, _ in _user_sessions(user):
        if except_key and s.session_key == except_key:
            continue
        s.delete()
        deleted += 1
    return deleted


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def status(request):
    tf = TwoFactor.objects.filter(user=request.user).first()
    return Response({
        'enabled': bool(tf and tf.enabled),
        'recovery_codes_remaining': len(tf.recovery_codes) if (tf and tf.enabled) else 0,
        'last_used_at': tf.last_used_at if tf else None,
        'locked_until': tf.locked_until if (tf and tf.locked_until and tf.locked_until > timezone.now()) else None,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='10/h', block=False)
def enroll(request):
    if getattr(request, 'limited', False):
        return Response({'error': 'Too many requests.'}, status=429)

    tf, _ = TwoFactor.objects.get_or_create(user=request.user)
    if tf.enabled:
        return Response({'error': '2FA is already enabled. Disable it first to re-enroll.'}, status=409)

    plain = pyotp.random_base32()
    tf.secret = _encrypt_secret(plain)
    tf.last_totp_step = 0
    tf.failed_attempts = 0
    tf.locked_until = None
    tf.save(update_fields=['secret', 'last_totp_step', 'failed_attempts', 'locked_until'])

    totp = pyotp.TOTP(plain)
    uri = totp.provisioning_uri(name=request.user.email or request.user.username, issuer_name=ISSUER)
    return Response({
        'secret': plain,            # shown once, scanned by user — never logged
        'provisioning_uri': uri,
        'qr_data_url': _qr_data_url(uri),
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='20/h', block=False)
def verify_enroll(request):
    if getattr(request, 'limited', False):
        return Response({'error': 'Too many requests.'}, status=429)

    code = (request.data.get('code') or '').strip()
    tf = TwoFactor.objects.filter(user=request.user).first()
    if tf is None or not tf.secret:
        return Response({'error': 'No pending 2FA setup. Call /enroll first.'}, status=400)
    if tf.enabled:
        return Response({'error': '2FA already enabled.'}, status=409)
    if not code or not code.isdigit() or len(code) != 6:
        return Response({'error': 'Enter the 6-digit code from your authenticator app.'}, status=400)

    plain = _decrypt_secret(tf.secret)
    matched = _verify_totp(plain, code, tf.last_totp_step)
    if matched is None:
        return Response({'error': 'Wrong code. Make sure your device clock is accurate.'}, status=400)

    plaintexts, hashes = _new_recovery_codes()
    tf.recovery_codes = hashes
    tf.enabled = True
    tf.enrolled_at = timezone.now()
    tf.last_totp_step = matched
    tf.failed_attempts = 0
    tf.locked_until = None
    tf.save()
    log.info('2FA enabled for user_id=%s', request.user.pk)
    return Response({
        'enabled': True,
        'recovery_codes': plaintexts,  # show once; never returned again
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable(request):
    """Require password + a valid TOTP/recovery code to turn 2FA off.
    Also revokes all *other* sessions — if a stolen session disabled 2FA, the
    legitimate user's other sessions get killed too, but more importantly the
    real user's panic-button login can clean up an attacker's session."""
    password = request.data.get('password') or ''
    code = (request.data.get('code') or '').strip()
    if not request.user.check_password(password):
        return Response({'error': 'Wrong password.'}, status=401)
    if not verify_for_login(request.user, code):
        return Response({'error': 'Wrong 2FA code.'}, status=401)

    TwoFactor.objects.filter(user=request.user).delete()
    revoked = _revoke_user_sessions(request.user, except_key=request.session.session_key)
    log.info('2FA disabled for user_id=%s; revoked %d other session(s)', request.user.pk, revoked)
    return Response({'enabled': False, 'sessions_revoked': revoked})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_recovery_codes(request):
    code = (request.data.get('code') or '').strip()
    tf = TwoFactor.objects.filter(user=request.user, enabled=True).first()
    if tf is None:
        return Response({'error': '2FA is not enabled.'}, status=400)
    if not verify_for_login(request.user, code):
        return Response({'error': 'Wrong 2FA code.'}, status=401)
    plaintexts, hashes = _new_recovery_codes()
    tf.recovery_codes = hashes
    tf.save(update_fields=['recovery_codes'])
    log.info('2FA recovery codes regenerated for user_id=%s', request.user.pk)
    return Response({'recovery_codes': plaintexts})
