"""TOTP-based 2FA: enroll, verify, disable, and login plug-in."""
import base64
import hashlib
import hmac
import io
import secrets
from datetime import timedelta

import pyotp
import qrcode
from django.conf import settings
from django.utils import timezone
from django_ratelimit.decorators import ratelimit
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from rest_framework.response import Response

from .models import TwoFactor

ISSUER = 'NVIDIA Chat Hub'
RECOVERY_CODE_COUNT = 10


def _hash_recovery(code: str) -> str:
    pepper = settings.SECRET_KEY.encode()
    # Lowercase + strip whitespace and dashes so users can paste however they typed.
    norm = code.strip().lower().replace('-', '').replace(' ', '')
    return hmac.new(pepper, norm.encode(), hashlib.sha256).hexdigest()


def _new_recovery_codes(n=RECOVERY_CODE_COUNT):
    """Plaintext (returned once) and HMAC list (stored). Format: 'xxxx-xxxx'."""
    plaintexts = []
    hashes = []
    for _ in range(n):
        raw = secrets.token_hex(4) + '-' + secrets.token_hex(4)
        plaintexts.append(raw)
        hashes.append(_hash_recovery(raw))
    return plaintexts, hashes


def _qr_data_url(provisioning_uri: str) -> str:
    """SVG QR — no PIL/Pillow dep, scales to any size in the browser."""
    from qrcode.image.svg import SvgImage
    img = qrcode.make(provisioning_uri, image_factory=SvgImage)
    buf = io.BytesIO()
    img.save(buf)
    return 'data:image/svg+xml;base64,' + base64.b64encode(buf.getvalue()).decode()


def verify_for_login(user, code: str) -> bool:
    """Called by auth_login. Returns True if `code` is a valid TOTP code or
    an unused recovery code for this user. Recovery codes are consumed."""
    tf = TwoFactor.objects.filter(user=user, enabled=True).first()
    if tf is None:
        return True  # no 2FA enabled = nothing to verify

    code = (code or '').strip()
    if not code:
        return False

    # Pure-digit codes try TOTP first.
    if code.isdigit() and len(code) == 6:
        if pyotp.TOTP(tf.secret).verify(code, valid_window=1):
            tf.last_used_at = timezone.now()
            tf.save(update_fields=['last_used_at'])
            return True

    # Otherwise treat as recovery code.
    h = _hash_recovery(code)
    if h in tf.recovery_codes:
        remaining = [x for x in tf.recovery_codes if x != h]
        tf.recovery_codes = remaining
        tf.last_used_at = timezone.now()
        tf.save(update_fields=['recovery_codes', 'last_used_at'])
        return True

    return False


def login_requires_2fa(user) -> bool:
    return TwoFactor.objects.filter(user=user, enabled=True).exists()


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def status(request):
    tf = TwoFactor.objects.filter(user=request.user).first()
    return Response({
        'enabled': bool(tf and tf.enabled),
        'recovery_codes_remaining': len(tf.recovery_codes) if (tf and tf.enabled) else 0,
        'last_used_at': tf.last_used_at if tf else None,
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

    # Always rotate the secret on a fresh enroll; otherwise an attacker who got
    # a half-completed enrollment could still finish it later.
    tf.secret = pyotp.random_base32()
    tf.save(update_fields=['secret'])

    totp = pyotp.TOTP(tf.secret)
    uri = totp.provisioning_uri(name=request.user.email or request.user.username, issuer_name=ISSUER)
    return Response({
        'secret': tf.secret,
        'provisioning_uri': uri,
        'qr_data_url': _qr_data_url(uri),
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='20/h', block=False)
def verify_enroll(request):
    """Confirm the user has scanned the QR by submitting a working code, then
    flip enabled=True and return one-time recovery codes."""
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
    if not pyotp.TOTP(tf.secret).verify(code, valid_window=1):
        return Response({'error': 'Wrong code. Make sure your device clock is accurate.'}, status=400)

    plaintexts, hashes = _new_recovery_codes()
    tf.recovery_codes = hashes
    tf.enabled = True
    tf.enrolled_at = timezone.now()
    tf.save()
    return Response({
        'enabled': True,
        'recovery_codes': plaintexts,  # show once; never returned again
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def disable(request):
    """Require password + a valid TOTP/recovery code to turn 2FA off."""
    password = request.data.get('password') or ''
    code = (request.data.get('code') or '').strip()
    if not request.user.check_password(password):
        return Response({'error': 'Wrong password.'}, status=401)
    if not verify_for_login(request.user, code):
        return Response({'error': 'Wrong 2FA code.'}, status=401)

    TwoFactor.objects.filter(user=request.user).delete()
    return Response({'enabled': False})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def regenerate_recovery_codes(request):
    """Issues a fresh batch (and invalidates the old ones). Requires current code."""
    code = (request.data.get('code') or '').strip()
    tf = TwoFactor.objects.filter(user=request.user, enabled=True).first()
    if tf is None:
        return Response({'error': '2FA is not enabled.'}, status=400)
    if not verify_for_login(request.user, code):
        return Response({'error': 'Wrong 2FA code.'}, status=401)
    plaintexts, hashes = _new_recovery_codes()
    tf.recovery_codes = hashes
    tf.save(update_fields=['recovery_codes'])
    return Response({'recovery_codes': plaintexts})
