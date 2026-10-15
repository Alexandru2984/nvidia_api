"""TOTP-based 2FA: enroll, verify, disable, and login plug-in.

Hardening notes:
- TOTP and recovery artifacts use independently configured, versioned root keys;
  rotating Django's signing key cannot silently lock users out.
- Recovery code consumption runs inside select_for_update so two concurrent
  logins with the same code can't both succeed.
- Replay protection: every accepted TOTP code marks its 30-second step on the
  TwoFactor row; future requests with the same step are rejected even if the
  code itself is still inside the validity window.
- Per-account brute-force lockout: 5 failures → 10-minute lock on the TOTP
  factor (recovery codes still honoured so users can recover).
"""
import base64
import binascii
import hashlib
import hmac
import io
import logging
import re
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
from .recent_auth import confirm_recent_auth, recent_auth_seconds_remaining

log = logging.getLogger(__name__)
security_log = logging.getLogger('security')

ISSUER = 'AI Chat Hub'
STAFF_2FA_SESSION_KEY = 'staff_2fa_verified_user_id'
ENROLLMENT_AUTH_SESSION_KEY = 'two_factor_recent_auth'
RECENT_AUTH_TTL_SECONDS = 5 * 60
RECOVERY_CODE_COUNT = 10
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = timedelta(minutes=10)
TOTP_STEP_SECONDS = 30
TOTP_VALID_WINDOW = 1  # accept current step ± 1
KEY_ENVELOPE_VERSION = 'v1'
KEY_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
TOTP_SECRET_RE = re.compile(r'^[A-Z2-7]{32}$')
RECOVERY_DIGEST_RE = re.compile(r'^[0-9a-f]{64}$')


class TwoFactorKeyError(ValueError):
    """Stored 2FA material cannot be safely opened with configured keys."""


def _root_key(key_id: str) -> bytes:
    encoded = settings.TWO_FACTOR_KEYS.get(key_id)
    if not isinstance(encoded, str):
        raise TwoFactorKeyError('unknown key identifier')
    try:
        decoded = base64.b64decode(encoded.encode('ascii'), altchars=b'-_', validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise TwoFactorKeyError('invalid configured key') from exc
    if len(decoded) != 32:
        raise TwoFactorKeyError('invalid configured key length')
    return decoded


def _derived_key(key_id: str, purpose: bytes) -> bytes:
    return hmac.new(_root_key(key_id), purpose, hashlib.sha256).digest()


def _active_key_id() -> str:
    key_id = settings.TWO_FACTOR_ACTIVE_KEY_ID
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        raise TwoFactorKeyError('invalid active key identifier')
    _root_key(key_id)
    return key_id


def _envelope(key_id: str, payload: str) -> str:
    return f'{KEY_ENVELOPE_VERSION}${key_id}${payload}'


def _parse_envelope(stored: str):
    if not isinstance(stored, str) or not stored:
        raise TwoFactorKeyError('empty stored artifact')
    if '$' not in stored:
        return None
    parts = stored.split('$', 2)
    if (
        len(parts) != 3
        or parts[0] != KEY_ENVELOPE_VERSION
        or not KEY_ID_RE.fullmatch(parts[1])
        or not parts[2]
    ):
        raise TwoFactorKeyError('invalid artifact envelope')
    return parts[1], parts[2]


def _validate_totp_secret(secret: str) -> str:
    if not isinstance(secret, str) or not TOTP_SECRET_RE.fullmatch(secret):
        raise TwoFactorKeyError('invalid TOTP secret')
    return secret


def _fernet(key_id: str):
    key = base64.urlsafe_b64encode(_derived_key(
        key_id, b'aichat:two-factor:fernet:v1',
    ))
    return Fernet(key)


def _legacy_fernet():
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode('utf-8')).digest())
    return Fernet(key)


def _encrypt_secret(plain: str) -> str:
    plain = _validate_totp_secret(plain)
    key_id = _active_key_id()
    token = _fernet(key_id).encrypt(plain.encode('ascii')).decode('ascii')
    return _envelope(key_id, token)


def _decrypt_secret(stored: str) -> str:
    """Open and validate a TOTP secret, rejecting corruption fail-closed."""
    parsed = _parse_envelope(stored)
    if parsed is not None:
        key_id, token = parsed
        try:
            plain = _fernet(key_id).decrypt(token.encode('ascii')).decode('ascii')
        except (InvalidToken, UnicodeDecodeError, UnicodeEncodeError, ValueError) as exc:
            raise TwoFactorKeyError('encrypted TOTP secret could not be opened') from exc
        return _validate_totp_secret(plain)

    if not settings.TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED:
        raise TwoFactorKeyError('unversioned TOTP secret is disabled')
    try:
        plain = _legacy_fernet().decrypt(stored.encode('ascii')).decode('ascii')
    except (InvalidToken, UnicodeDecodeError, UnicodeEncodeError, ValueError):
        plain = stored
    return _validate_totp_secret(plain)


def _secret_key_id(stored: str):
    parsed = _parse_envelope(stored)
    return parsed[0] if parsed is not None else None


def _normalise_recovery_code(code: str) -> str:
    return code.strip().lower().replace('-', '').replace(' ', '')


def _hash_recovery(code: str, *, key_id=None) -> str:
    key_id = key_id or _active_key_id()
    pepper = _derived_key(key_id, b'aichat:two-factor:recovery:v1')
    digest = hmac.new(
        pepper, _normalise_recovery_code(code).encode('utf-8'), hashlib.sha256,
    ).hexdigest()
    return _envelope(key_id, digest)


def _legacy_recovery_digest(code: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode('utf-8'),
        _normalise_recovery_code(code).encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()


def _matching_recovery_artifact(stored_codes, code: str):
    if not isinstance(stored_codes, list):
        raise TwoFactorKeyError('invalid recovery-code collection')
    legacy_digest = None
    for stored in stored_codes:
        parsed = _parse_envelope(stored)
        if parsed is None:
            if not settings.TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED:
                raise TwoFactorKeyError('unversioned recovery code is disabled')
            if not RECOVERY_DIGEST_RE.fullmatch(stored):
                raise TwoFactorKeyError('invalid legacy recovery digest')
            if legacy_digest is None:
                legacy_digest = _legacy_recovery_digest(code)
            candidate = legacy_digest
        else:
            key_id, digest = parsed
            if not RECOVERY_DIGEST_RE.fullmatch(digest):
                raise TwoFactorKeyError('invalid recovery digest')
            candidate = _hash_recovery(code, key_id=key_id).split('$', 2)[2]
        if hmac.compare_digest(candidate, parsed[1] if parsed is not None else stored):
            return stored
    return None


def _new_recovery_codes(n=RECOVERY_CODE_COUNT):
    plaintexts = []
    hashes = []
    for _ in range(n):
        raw = secrets.token_hex(4) + '-' + secrets.token_hex(4)
        plaintexts.append(raw)
        hashes.append(_hash_recovery(raw))
    return plaintexts, hashes


def _enrollment_fingerprint(encrypted_secret: str) -> str:
    parsed = _parse_envelope(encrypted_secret)
    if parsed is None:
        if not settings.TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED:
            raise TwoFactorKeyError('unversioned enrollment is disabled')
        pepper = settings.SECRET_KEY.encode('utf-8')
    else:
        pepper = _derived_key(parsed[0], b'aichat:two-factor:enrollment:v1')
    return hmac.new(
        pepper,
        f'two-factor-enrollment:{encrypted_secret}'.encode(),
        hashlib.sha256,
    ).hexdigest()


def _mark_recent_enrollment_auth(request, encrypted_secret: str):
    request.session[ENROLLMENT_AUTH_SESSION_KEY] = {
        'user_id': str(request.user.pk),
        'authenticated_at': int(time.time()),
        'enrollment': _enrollment_fingerprint(encrypted_secret),
    }


def _has_recent_enrollment_auth(request, encrypted_secret: str) -> bool:
    marker = request.session.get(ENROLLMENT_AUTH_SESSION_KEY)
    if not isinstance(marker, dict):
        return False
    authenticated_at = marker.get('authenticated_at')
    if not isinstance(authenticated_at, int):
        return False
    age = int(time.time()) - authenticated_at
    enrollment = marker.get('enrollment')
    return (
        0 <= age <= RECENT_AUTH_TTL_SECONDS
        and marker.get('user_id') == str(request.user.pk)
        and isinstance(enrollment, str)
        and hmac.compare_digest(enrollment, _enrollment_fingerprint(encrypted_secret))
    )


def _rotate_and_revoke_other_sessions(request, *, mark_staff=False):
    """Replace the bearer session after a factor change and kill all others."""
    from .sessions import sync_session_record

    request.session.cycle_key()
    if mark_staff:
        mark_staff_2fa_verified(request, request.user)
    sync_session_record(request)
    return _revoke_user_sessions(request.user, except_key=request.session.session_key)


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


def _report_key_error(user_id, operation):
    security_log.error(
        'event=two_factor_key_error operation=%s user_id=%s', operation, user_id,
    )


def verify_for_login(user, code: str) -> bool:
    """True if `code` is a valid TOTP or unused recovery code for `user`.
    Recovery codes are consumed atomically; TOTP replays are rejected."""
    if not isinstance(code, str):
        return False
    code = code.strip()
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

        is_totp = code.isdigit() and len(code) == 6

        # Recovery codes remain usable during a TOTP brute-force lockout. Their
        # longer, hyphenated format cannot be confused with a six-digit TOTP.
        if not is_totp:
            try:
                matched_artifact = _matching_recovery_artifact(tf.recovery_codes or [], code)
            except TwoFactorKeyError:
                _report_key_error(user.pk, 'recovery_login')
                return False
            if matched_artifact is not None:
                tf.recovery_codes = [
                    artifact for artifact in tf.recovery_codes
                    if artifact != matched_artifact
                ]
                tf.last_used_at = timezone.now()
                tf.failed_attempts = 0
                tf.locked_until = None
                tf.save(update_fields=[
                    'recovery_codes', 'last_used_at', 'failed_attempts', 'locked_until',
                ])
                log.info(
                    '2FA recovery code consumed for user_id=%s; %d remaining',
                    user.pk, len(tf.recovery_codes),
                )
                return True
            if tf.locked_until and tf.locked_until > timezone.now():
                return False
            _record_failure(tf)
            return False

        # Locked? Reject TOTP without burning the failure counter further.
        if tf.locked_until and tf.locked_until > timezone.now():
            return False

        try:
            plain = _decrypt_secret(tf.secret)
        except TwoFactorKeyError:
            _report_key_error(user.pk, 'totp_login')
            return False

        # TOTP path
        matched = _verify_totp(plain, code, tf.last_totp_step)
        if matched is not None:
            update_fields = [
                'last_totp_step', 'last_used_at', 'failed_attempts', 'locked_until',
            ]
            if _secret_key_id(tf.secret) != _active_key_id():
                tf.secret = _encrypt_secret(plain)
                update_fields.append('secret')
            tf.last_totp_step = matched
            tf.last_used_at = timezone.now()
            tf.failed_attempts = 0
            tf.locked_until = None
            tf.save(update_fields=update_fields)
            return True

        _record_failure(tf)
        return False


def login_requires_2fa(user) -> bool:
    return TwoFactor.objects.filter(user=user, enabled=True).exists()


def mark_staff_2fa_verified(request, user):
    if user.is_staff:
        request.session[STAFF_2FA_SESSION_KEY] = str(user.pk)


def staff_2fa_verified(request):
    user = request.user
    return (
        user.is_authenticated
        and user.is_staff
        and request.session.get(STAFF_2FA_SESSION_KEY) == str(user.pk)
        and login_requires_2fa(user)
    )


def _revoke_user_sessions(user, except_key=None):
    """Sign the user out everywhere (optionally keeping one session). Used on
    sensitive auth changes — disable 2FA, regen recovery codes, password reset."""
    from .sessions import revoke_user_sessions

    return revoke_user_sessions(user, except_key=except_key)


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

    if TwoFactor.objects.filter(user=request.user, enabled=True).exists():
        return Response({'error': '2FA is already enabled. Disable it first to re-enroll.'}, status=409)
    response = confirm_recent_auth(request, request.data.get('password') or '')
    if response is not None:
        return response

    tf, _ = TwoFactor.objects.get_or_create(user=request.user)
    plain = pyotp.random_base32()
    tf.secret = _encrypt_secret(plain)
    tf.last_totp_step = 0
    tf.failed_attempts = 0
    tf.locked_until = None
    tf.save(update_fields=['secret', 'last_totp_step', 'failed_attempts', 'locked_until'])
    _mark_recent_enrollment_auth(request, tf.secret)

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

    raw_code = request.data.get('code')
    code = raw_code.strip() if isinstance(raw_code, str) else ''
    if not code or not code.isdigit() or len(code) != 6:
        return Response({'error': 'Enter the 6-digit code from your authenticator app.'}, status=400)

    with transaction.atomic():
        tf = (TwoFactor.objects
              .select_for_update()
              .filter(user=request.user)
              .first())
        if tf is None or not tf.secret:
            return Response({'error': 'No pending 2FA setup. Call /enroll first.'}, status=400)
        if tf.enabled:
            return Response({'error': '2FA already enabled.'}, status=409)
        try:
            recent_enrollment_auth = _has_recent_enrollment_auth(request, tf.secret)
        except TwoFactorKeyError:
            request.session.pop(ENROLLMENT_AUTH_SESSION_KEY, None)
            _report_key_error(request.user.pk, 'verify_enrollment')
            return Response(
                {'error': 'Two-factor setup is temporarily unavailable.'}, status=503,
            )
        if not recent_enrollment_auth or recent_auth_seconds_remaining(request) <= 0:
            request.session.pop(ENROLLMENT_AUTH_SESSION_KEY, None)
            return Response({'error': 'Password confirmation expired. Start 2FA setup again.'}, status=403)

        try:
            plain = _decrypt_secret(tf.secret)
        except TwoFactorKeyError:
            request.session.pop(ENROLLMENT_AUTH_SESSION_KEY, None)
            _report_key_error(request.user.pk, 'verify_enrollment')
            return Response(
                {'error': 'Two-factor setup is temporarily unavailable.'}, status=503,
            )
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

    request.session.pop(ENROLLMENT_AUTH_SESSION_KEY, None)
    revoked = _rotate_and_revoke_other_sessions(request, mark_staff=True)
    security_log.warning('event=two_factor_enabled user_id=%s', request.user.pk)
    return Response({
        'enabled': True,
        'recovery_codes': plaintexts,  # show once; never returned again
        'sessions_revoked': revoked,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='10/h', block=False)
def disable(request):
    """Require password + a valid TOTP/recovery code to turn 2FA off.
    Also revokes all *other* sessions — if a stolen session disabled 2FA, the
    legitimate user's other sessions get killed too, but more importantly the
    real user's panic-button login can clean up an attacker's session."""
    if getattr(request, 'limited', False):
        return Response({'error': 'Too many requests.'}, status=429)
    response = confirm_recent_auth(
        request,
        request.data.get('password') or '',
        request.data.get('code') or '',
    )
    if response is not None:
        return response
    with transaction.atomic():
        TwoFactor.objects.filter(user=request.user).delete()
    request.session.pop(STAFF_2FA_SESSION_KEY, None)
    request.session.pop(ENROLLMENT_AUTH_SESSION_KEY, None)
    revoked = _rotate_and_revoke_other_sessions(request)
    security_log.warning('event=two_factor_disabled user_id=%s sessions_revoked=%s',
                         request.user.pk, revoked)
    return Response({'enabled': False, 'sessions_revoked': revoked})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='5/h', block=False)
def regenerate_recovery_codes(request):
    if getattr(request, 'limited', False):
        return Response({'error': 'Too many requests.'}, status=429)
    if not TwoFactor.objects.filter(user=request.user, enabled=True).exists():
        return Response({'error': '2FA is not enabled.'}, status=400)
    response = confirm_recent_auth(
        request,
        request.data.get('password') or '',
        request.data.get('code') or '',
    )
    if response is not None:
        return response
    with transaction.atomic():
        plaintexts, hashes = _new_recovery_codes()
        TwoFactor.objects.filter(user=request.user, enabled=True).update(recovery_codes=hashes)
    revoked = _rotate_and_revoke_other_sessions(request, mark_staff=True)
    security_log.warning('event=recovery_codes_regenerated user_id=%s', request.user.pk)
    return Response({'recovery_codes': plaintexts, 'sessions_revoked': revoked})
