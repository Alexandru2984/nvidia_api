import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
from datetime import timedelta
from pathlib import Path

import requests
from django.conf import settings
from django.contrib.auth import (
    authenticate,
    get_user_model,
    update_session_auth_hash,
)
from django.contrib.auth import (
    login as django_login,
)
from django.contrib.auth import (
    logout as django_logout,
)
from django.contrib.auth.password_validation import validate_password
from django.core import signing
from django.core.exceptions import ValidationError
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Count, Exists, OuterRef, Q, Sum
from django.http import FileResponse, Http404, StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.csrf import ensure_csrf_cookie
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .attachments import content_fingerprint, detect_mime, extract_text, kind_for_mime
from .model_status import get_status, unavailable_model_ids
from .models import (
    Attachment,
    Conversation,
    EmailVerification,
    Message,
    PasswordReset,
    RegistrationInvite,
)
from .models_catalog import (
    DEFAULT_IMAGE_GEN_MODEL_ID,
    DEFAULT_MODEL_ID,
    IMAGE_GEN_MODEL_IDS,
    IMAGE_GEN_MODELS,
    MODEL_BY_ID,
    MODEL_IDS,
    NVIDIA_MODELS,
    attachment_capability_issue,
    model_capabilities,
)
from .registration import hash_invite_code
from .security_events import actor_for_request, security_log
from .serializers import (
    AttachmentSerializer,
    ConversationDetailSerializer,
    ConversationListSerializer,
    MessageSerializer,
)
from .sessions import stamp_session
from .twofactor import (
    _revoke_user_sessions,
    login_requires_2fa,
    mark_staff_2fa_verified,
    verify_for_login,
)
from .usage import (
    finalize_chat_usage,
    next_reset,
    reserve_ai_request,
    user_usage_snapshot,
)

log = logging.getLogger(__name__)


def _rate_limited(request):
    if not getattr(request, 'limited', False):
        return None
    security_log.warning('event=rate_limit path=%s actor=%s',
                         request.path[:160], actor_for_request(request))
    return Response({'error': 'Too many requests. Slow down and try again.'}, status=429)


def _reserve_provider_call(request, kind, prompt_characters=0, token_reservation=0, day=None):
    reason = reserve_ai_request(
        request.user,
        kind,
        prompt_characters,
        token_reservation=token_reservation,
        day=day,
    )
    if reason is None:
        return None
    if reason == 'disabled':
        security_log.warning('event=ai_budget_blocked scope=disabled kind=%s user_id=%s',
                             kind, request.user.pk)
        return Response(
            {'error': 'AI generation is temporarily disabled.', 'code': reason},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    reset, retry_after = next_reset()
    is_global = reason in {'global_daily_limit', 'global_daily_token_limit'}
    is_token_limit = reason in {'global_daily_token_limit', 'user_daily_token_limit'}
    security_log.warning('event=ai_budget_blocked scope=%s kind=%s user_id=%s',
                         'global' if is_global else 'user', kind, request.user.pk)
    response = Response({
        'error': (
            'The service-wide daily AI budget has been reached. Try again after the UTC reset.'
            if is_global else
            (
                'Your daily AI token budget has been reached. Try again after the UTC reset.'
                if is_token_limit else
                f'Your daily {kind} generation limit has been reached. Try again after the UTC reset.'
            )
        ),
        'code': reason,
        'resets_at': reset.isoformat().replace('+00:00', 'Z'),
    }, status=status.HTTP_503_SERVICE_UNAVAILABLE if is_global else status.HTTP_429_TOO_MANY_REQUESTS)
    response['Retry-After'] = str(retry_after)
    return response


@api_view(['GET'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def auth_me(request):
    return Response({
        'username': request.user.username if request.user.is_authenticated else None,
        'registration_mode': settings.REGISTRATION_MODE,
    })


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='10/m', block=False)
def auth_login(request):
    if (r := _rate_limited(request)): return r
    username = (request.data.get('username') or '').strip()
    password = request.data.get('password') or ''
    if not username or not password:
        return Response({'error': 'username and password required'}, status=status.HTTP_400_BAD_REQUEST)
    if len(password) > settings.MAX_PASSWORD_LENGTH:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    user = authenticate(request, username=username, password=password)
    if user is None:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    verified_2fa = False
    if login_requires_2fa(user):
        code = (request.data.get('code') or '').strip()
        if not code:
            return Response({'error': 'Two-factor code required.', 'two_factor_required': True},
                            status=status.HTTP_401_UNAUTHORIZED)
        if not verify_for_login(user, code):
            return Response({'error': 'Invalid 2FA code.', 'two_factor_required': True},
                            status=status.HTTP_401_UNAUTHORIZED)
        verified_2fa = True
    django_login(request, user)
    if verified_2fa:
        mark_staff_2fa_verified(request, user)
    stamp_session(request)
    return Response({'username': user.username})


@api_view(['POST'])
def auth_logout(request):
    django_logout(request)
    return Response({'ok': True})


USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,30}$')

OTP_TTL_SECONDS = 30 * 60       # code valid 30 min
RESEND_COOLDOWN_SECONDS = 60    # 1 min between resends
MAX_VERIFY_ATTEMPTS = 6
GENERIC_CODE_ERROR = 'Invalid or expired email or code.'


def _hash_code(code: str) -> str:
    pepper = settings.SECRET_KEY.encode()
    return hmac.new(pepper, code.encode(), hashlib.sha256).hexdigest()


def _generate_code() -> str:
    return f'{secrets.randbelow(1_000_000):06d}'


def _registration_response(email):
    return Response({
        'message': 'If the account details are available, check your email for the 6-digit code.',
        'email': email,
        'resend_available_in': RESEND_COOLDOWN_SECONDS,
    }, status=201)


def _registration_mode_response(code, message):
    return Response({'error': message, 'code': code}, status=status.HTTP_403_FORBIDDEN)


def _resend_response():
    return Response({
        'message': 'If your account is awaiting verification, a new code has been sent.',
        'resend_available_in': RESEND_COOLDOWN_SECONDS,
    })


def _send_verification_email(user, code):
    subject = 'Your AI Chat Hub verification code'
    text = (
        f'Hi {user.username},\n\n'
        f'Your verification code is: {code}\n\n'
        f'Enter this code on the verification page to activate your account.\n'
        f'The code expires in 30 minutes.\n\n'
        f"If you didn't create an account, you can ignore this email.\n\n"
        f'— AI Chat Hub\n'
    )
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{subject}</title></head>
<body style="margin:0;padding:0;background:#0a0d12;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e6edf3;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0d12;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#11161d;border:1px solid #232a36;border-radius:14px;overflow:hidden;">
        <tr><td style="padding:28px 28px 8px 28px;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="width:36px;height:36px;background:#76b900;color:#0a0d12;border-radius:8px;font-weight:800;font-size:18px;text-align:center;vertical-align:middle;">N</td>
            <td style="padding-left:12px;font-weight:600;font-size:16px;color:#e6edf3;">AI Chat Hub</td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:8px 28px 0 28px;">
          <h1 style="margin:18px 0 8px 0;font-size:20px;font-weight:600;color:#e6edf3;">Verify your email</h1>
          <p style="margin:0 0 18px 0;font-size:14px;line-height:1.55;color:#8b96a8;">
            Hi <strong style="color:#e6edf3;">{user.username}</strong>, use the code below to finish creating your account.
          </p>
        </td></tr>
        <tr><td style="padding:0 28px;">
          <div style="background:#0a0d12;border:1px solid #232a36;border-radius:12px;padding:22px 16px;text-align:center;">
            <div style="font-size:11px;letter-spacing:2px;color:#8b96a8;text-transform:uppercase;margin-bottom:8px;">Verification code</div>
            <div style="font-size:34px;letter-spacing:10px;font-weight:700;color:#76b900;font-family:'SFMono-Regular',Menlo,Consolas,monospace;">{code}</div>
            <div style="font-size:12px;color:#8b96a8;margin-top:10px;">Expires in 30 minutes</div>
          </div>
        </td></tr>
        <tr><td style="padding:18px 28px 26px 28px;">
          <p style="margin:0;font-size:12px;line-height:1.55;color:#8b96a8;">
            If you didn't sign up for AI Chat Hub, you can ignore this email — your address won't be used.
          </p>
        </td></tr>
        <tr><td style="padding:14px 28px;border-top:1px solid #232a36;background:#0e131a;">
          <p style="margin:0;font-size:11px;color:#5f6b7d;">
            This is an automated message from <a href="{settings.FRONTEND_URL}" style="color:#76b900;text-decoration:none;">AI Chat Hub</a>.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""
    msg = EmailMultiAlternatives(subject, text, settings.DEFAULT_FROM_EMAIL, [user.email])
    msg.attach_alternative(html, 'text/html')
    msg.send(fail_silently=False)


def _issue_new_code(user):
    code = _generate_code()
    now = timezone.now()
    EmailVerification.objects.update_or_create(
        user=user,
        defaults={
            'code_hash': _hash_code(code),
            'sent_at': now,
            'expires_at': now + timedelta(seconds=OTP_TTL_SECONDS),
            'attempts': 0,
        },
    )
    _send_verification_email(user, code)


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='5/h', block=False)
def auth_register(request):
    if (r := _rate_limited(request)): return r
    username = (request.data.get('username') or '').strip()
    email = (request.data.get('email') or '').strip().lower()
    password = request.data.get('password') or ''
    honeypot = (request.data.get('website') or '').strip()
    registration_mode = settings.REGISTRATION_MODE

    if registration_mode == 'closed':
        security_log.info('event=registration_blocked mode=closed actor=%s', actor_for_request(request))
        return _registration_mode_response(
            'registration_closed', 'Registration is currently unavailable.',
        )

    # Validation runs *before* the honeypot check so the response shape for
    # malformed input is identical with or without the honeypot field. That
    # makes the honeypot harder to fingerprint by submitting bad data twice.
    if not USERNAME_RE.match(username):
        return Response({'error': 'Username must be 3-30 chars, letters/digits/underscore only.'}, status=400)
    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email address.'}, status=400)
    if len(password) < 8 or len(password) > settings.MAX_PASSWORD_LENGTH:
        return Response({'error': f'Password must be 8-{settings.MAX_PASSWORD_LENGTH} characters.'}, status=400)

    # Honeypot fires only after the request would have succeeded. Bots that
    # fill every field still get the same 201 a real user gets, but no row
    # is written and no email goes out.
    if honeypot:
        security_log.warning('event=registration_honeypot actor=%s', actor_for_request(request))
        return _registration_response(email)

    User = get_user_model()
    user = User(username=username, email=email, is_active=False)
    try:
        validate_password(password, user)
    except ValidationError as e:
        return Response({'error': ' '.join(e.messages)}, status=400)

    invite_hash = None
    if registration_mode == 'invite':
        invite_hash = hash_invite_code(request.data.get('invite_code'))
        if invite_hash is None:
            security_log.warning(
                'event=registration_invite_rejected actor=%s', actor_for_request(request),
            )
            return _registration_mode_response(
                'invalid_invitation', 'A valid invitation code is required.',
            )

    used_invite_id = None
    try:
        with transaction.atomic():
            invite = None
            if invite_hash is not None:
                invite = RegistrationInvite.objects.select_for_update().filter(
                    code_hash=invite_hash,
                ).first()
                if invite is None or invite.used_at is not None or invite.expires_at <= timezone.now():
                    security_log.warning(
                        'event=registration_invite_rejected actor=%s', actor_for_request(request),
                    )
                    return _registration_mode_response(
                        'invalid_invitation', 'A valid invitation code is required.',
                    )

            # Keep duplicate username/email behavior opaque. In invite mode the
            # row lock also ensures a duplicate attempt cannot burn the code.
            if User.objects.filter(
                Q(username__iexact=username) | Q(email__iexact=email),
            ).exists():
                security_log.info('event=registration_suppressed actor=%s', actor_for_request(request))
                return _registration_response(email)

            # Do the expensive password hash only after invitation and duplicate
            # checks so random invalid codes cannot become a CPU-amplification path.
            user.set_password(password)
            user.save()
            _issue_new_code(user)
            if invite is not None:
                invite.used_at = timezone.now()
                invite.used_by = user
                invite.save(update_fields=['used_at', 'used_by'])
                used_invite_id = invite.pk
    except IntegrityError:
        security_log.info('event=registration_suppressed actor=%s', actor_for_request(request))
        return _registration_response(email)
    except Exception:
        log.exception('Failed to send verification email for user_id=%s', user.pk)
        # The surrounding transaction rolls back both user and invite usage so
        # the owner can retry after mail delivery recovers.
        return _registration_response(email)

    if used_invite_id is not None:
        security_log.warning(
            'event=registration_invite_consumed invite_id=%s user_id=%s actor=%s',
            used_invite_id, user.pk, actor_for_request(request),
        )
    return _registration_response(user.email)


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='10/m', block=False)
@transaction.atomic
def auth_verify(request):
    if (r := _rate_limited(request)): return r
    email = (request.data.get('email') or '').strip().lower()
    code = (request.data.get('code') or '').strip()
    if not email or not code:
        return Response({'error': 'Email and code required.'}, status=400)
    if not re.fullmatch(r'\d{6}', code):
        return Response({'error': 'Code must be 6 digits.'}, status=400)

    User = get_user_model()
    user = User.objects.select_for_update().filter(email__iexact=email).first()
    if user is None:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)
    if user.is_active:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)

    ev = EmailVerification.objects.filter(user=user).first()
    if ev is None:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)
    if ev.expires_at <= timezone.now():
        ev.delete()
        return Response({'error': GENERIC_CODE_ERROR}, status=400)
    if ev.attempts >= MAX_VERIFY_ATTEMPTS:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)

    if not hmac.compare_digest(ev.code_hash, _hash_code(code)):
        ev.attempts += 1
        ev.save(update_fields=['attempts'])
        return Response({'error': GENERIC_CODE_ERROR}, status=400)

    user.is_active = True
    user.save(update_fields=['is_active'])
    ev.delete()
    django_login(request, user)
    stamp_session(request)
    security_log.warning('event=registration_verified user_id=%s', user.pk)
    return Response({'verified': True, 'username': user.username})


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='5/h', block=False)
@transaction.atomic
def auth_resend(request):
    if (r := _rate_limited(request)): return r
    email = (request.data.get('email') or '').strip().lower()
    if not email:
        return Response({'error': 'Email required.'}, status=400)
    User = get_user_model()
    user = User.objects.select_for_update().filter(email__iexact=email, is_active=False).first()
    if user is None:
        return _resend_response()

    ev = EmailVerification.objects.filter(user=user).first()
    now = timezone.now()
    if ev is not None:
        elapsed = (now - ev.sent_at).total_seconds()
        if elapsed < RESEND_COOLDOWN_SECONDS:
            return _resend_response()

    try:
        with transaction.atomic():
            _issue_new_code(user)
    except Exception:
        log.exception('Failed to resend verification email for user_id=%s', user.pk)
        return _resend_response()

    return _resend_response()


def _send_password_reset_email(user, code):
    subject = 'Your AI Chat Hub password reset code'
    text = (
        f'Hi {user.username},\n\n'
        f'Your password reset code is: {code}\n\n'
        f'Enter this code along with a new password to reset your account.\n'
        f'The code expires in 30 minutes.\n\n'
        f"If you didn't request a reset, you can ignore this email — your password won't change.\n\n"
        f'— AI Chat Hub\n'
    )
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{subject}</title></head>
<body style="margin:0;padding:0;background:#0a0d12;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#e6edf3;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0d12;padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#11161d;border:1px solid #232a36;border-radius:14px;overflow:hidden;">
        <tr><td style="padding:28px 28px 8px 28px;">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td style="width:36px;height:36px;background:#76b900;color:#0a0d12;border-radius:8px;font-weight:800;font-size:18px;text-align:center;vertical-align:middle;">N</td>
            <td style="padding-left:12px;font-weight:600;font-size:16px;color:#e6edf3;">AI Chat Hub</td>
          </tr></table>
        </td></tr>
        <tr><td style="padding:8px 28px 0 28px;">
          <h1 style="margin:18px 0 8px 0;font-size:20px;font-weight:600;color:#e6edf3;">Reset your password</h1>
          <p style="margin:0 0 18px 0;font-size:14px;line-height:1.55;color:#8b96a8;">
            Hi <strong style="color:#e6edf3;">{user.username}</strong>, use the code below to set a new password.
          </p>
        </td></tr>
        <tr><td style="padding:0 28px;">
          <div style="background:#0a0d12;border:1px solid #232a36;border-radius:12px;padding:22px 16px;text-align:center;">
            <div style="font-size:11px;letter-spacing:2px;color:#8b96a8;text-transform:uppercase;margin-bottom:8px;">Reset code</div>
            <div style="font-size:34px;letter-spacing:10px;font-weight:700;color:#76b900;font-family:'SFMono-Regular',Menlo,Consolas,monospace;">{code}</div>
            <div style="font-size:12px;color:#8b96a8;margin-top:10px;">Expires in 30 minutes</div>
          </div>
        </td></tr>
        <tr><td style="padding:18px 28px 26px 28px;">
          <p style="margin:0;font-size:12px;line-height:1.55;color:#8b96a8;">
            If you didn't request this, you can ignore the email — your password stays the same.
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>"""
    msg = EmailMultiAlternatives(subject, text, settings.DEFAULT_FROM_EMAIL, [user.email])
    msg.attach_alternative(html, 'text/html')
    msg.send(fail_silently=False)


def _issue_password_reset(user):
    code = _generate_code()
    now = timezone.now()
    PasswordReset.objects.update_or_create(
        user=user,
        defaults={
            'code_hash': _hash_code(code),
            'sent_at': now,
            'expires_at': now + timedelta(seconds=OTP_TTL_SECONDS),
            'attempts': 0,
        },
    )
    _send_password_reset_email(user, code)


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='5/h', block=False)
@transaction.atomic
def auth_forgot(request):
    if (r := _rate_limited(request)): return r
    email = (request.data.get('email') or '').strip().lower()
    generic = Response({
        'message': 'If an account exists for that email, a reset code has been sent.',
        'resend_available_in': RESEND_COOLDOWN_SECONDS,
    })
    if not email:
        return Response({'error': 'Email required.'}, status=400)
    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email address.'}, status=400)

    User = get_user_model()
    user = User.objects.select_for_update().filter(email__iexact=email, is_active=True).first()
    if user is None:
        return generic

    existing = PasswordReset.objects.filter(user=user).first()
    if existing is not None:
        elapsed = (timezone.now() - existing.sent_at).total_seconds()
        if elapsed < RESEND_COOLDOWN_SECONDS:
            return generic

    try:
        with transaction.atomic():
            _issue_password_reset(user)
    except Exception:
        log.exception('Failed to send password reset email for user_id=%s', user.pk)
        return generic
    return generic


@api_view(['POST'])
@permission_classes([AllowAny])
@ratelimit(key='ip', rate='10/m', block=False)
@transaction.atomic
def auth_reset(request):
    if (r := _rate_limited(request)): return r
    email = (request.data.get('email') or '').strip().lower()
    code = (request.data.get('code') or '').strip()
    password = request.data.get('password') or ''
    if not email or not code or not password:
        return Response({'error': 'Email, code, and new password are required.'}, status=400)
    if not re.fullmatch(r'\d{6}', code):
        return Response({'error': 'Code must be 6 digits.'}, status=400)

    if len(password) > settings.MAX_PASSWORD_LENGTH:
        return Response({'error': f'Password must be at most {settings.MAX_PASSWORD_LENGTH} characters.'}, status=400)

    User = get_user_model()
    user = User.objects.select_for_update().filter(email__iexact=email, is_active=True).first()
    if user is None:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)

    pr = PasswordReset.objects.filter(user=user).first()
    if pr is None:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)
    if pr.expires_at <= timezone.now():
        pr.delete()
        return Response({'error': GENERIC_CODE_ERROR}, status=400)
    if pr.attempts >= MAX_VERIFY_ATTEMPTS:
        return Response({'error': GENERIC_CODE_ERROR}, status=400)

    if not hmac.compare_digest(pr.code_hash, _hash_code(code)):
        pr.attempts += 1
        pr.save(update_fields=['attempts'])
        return Response({'error': GENERIC_CODE_ERROR}, status=400)

    try:
        validate_password(password, user)
    except ValidationError as e:
        return Response({'error': ' '.join(e.messages)}, status=400)

    user.set_password(password)
    user.save(update_fields=['password'])
    pr.delete()

    # Killing every session of this user is the right behaviour after a
    # password change: anything signed in with the old password is potentially
    # the attacker. The frontend will need to re-login fresh.
    revoked = _revoke_user_sessions(user)

    # If the account has 2FA enabled, password alone isn't enough — refuse to
    # auto-login. The user must complete /auth/login/ with their TOTP code,
    # which closes the email-controls-account → 2FA-bypass hole.
    if login_requires_2fa(user):
        return Response({
            'reset': True,
            'username': user.username,
            'two_factor_required': True,
            'sessions_revoked': revoked,
        })

    django_login(request, user)
    stamp_session(request)
    return Response({'reset': True, 'username': user.username, 'sessions_revoked': revoked})


@api_view(['POST'])
@ratelimit(key='user', rate='10/h', block=False)
def auth_change_password(request):
    """Change password for the logged-in user. Requires the current password.
    Keeps this session alive, kills every other one."""
    if (r := _rate_limited(request)): return r
    current = request.data.get('current_password') or ''
    new = request.data.get('new_password') or ''
    if len(current) > settings.MAX_PASSWORD_LENGTH or not request.user.check_password(current):
        return Response({'error': 'Current password is incorrect.'}, status=status.HTTP_401_UNAUTHORIZED)
    if len(new) < 8 or len(new) > settings.MAX_PASSWORD_LENGTH:
        return Response({'error': f'Password must be 8-{settings.MAX_PASSWORD_LENGTH} characters.'}, status=400)
    try:
        validate_password(new, request.user)
    except ValidationError as e:
        return Response({'error': ' '.join(e.messages)}, status=400)

    request.user.set_password(new)
    request.user.save(update_fields=['password'])
    # Re-stamp this session's auth hash so the user isn't logged out here,
    # then revoke everything else (anything on the old password is suspect).
    update_session_auth_hash(request, request.user)
    revoked = _revoke_user_sessions(request.user, except_key=request.session.session_key)
    security_log.warning('event=password_changed user_id=%s sessions_revoked=%s',
                         request.user.pk, revoked)
    return Response({'changed': True, 'sessions_revoked': revoked})


@api_view(['POST'])
@ratelimit(key='user', rate='5/h', block=False)
def auth_delete_account(request):
    """Permanently delete the account. Requires the password, plus a valid
    TOTP/recovery code when 2FA is enabled. Cascades to conversations,
    messages and attachments (files removed via the pre_delete signal)."""
    if (r := _rate_limited(request)): return r
    password = request.data.get('password') or ''
    if len(password) > settings.MAX_PASSWORD_LENGTH or not request.user.check_password(password):
        return Response({'error': 'Wrong password.'}, status=status.HTTP_401_UNAUTHORIZED)
    if login_requires_2fa(request.user):
        code = (request.data.get('code') or '').strip()
        if not code:
            return Response({'error': 'Two-factor code required.', 'two_factor_required': True},
                            status=status.HTTP_401_UNAUTHORIZED)
        if not verify_for_login(request.user, code):
            return Response({'error': 'Invalid 2FA code.', 'two_factor_required': True},
                            status=status.HTTP_401_UNAUTHORIZED)

    user = request.user
    user_id = user.pk
    django_logout(request)
    user.delete()
    security_log.warning('event=account_deleted former_user_id=%s', user_id)
    return Response({'deleted': True})


@api_view(['GET'])
def list_models(request):
    runtime_status = get_status()
    down = unavailable_model_ids()
    probe_results = runtime_status.get('results', {})
    models = []
    for catalog_model in NVIDIA_MODELS:
        if catalog_model['id'] in down:
            continue
        model = dict(catalog_model)
        result = probe_results.get(model['id'])
        model['performance'] = _public_model_performance(result)
        models.append(model)
    default = _preferred_model_id(models)
    return Response({
        'models': models,
        'default': default,
        'availability_checked_at': runtime_status.get('checked_at'),
        'attachment_limits': {
            'max_files_per_message': settings.CHAT_MAX_ATTACHMENTS_PER_MESSAGE,
            'max_file_bytes': settings.MAX_ATTACHMENT_SIZE,
            'max_bytes_per_message': settings.CHAT_MAX_ATTACHMENT_BYTES_PER_MESSAGE,
        },
    })


def _public_model_performance(result):
    """Expose a coarse successful-probe sample, never private failure details."""
    if not isinstance(result, dict) or result.get('outcome') != 'available':
        return None
    latency_ms = result.get('latency_ms')
    if not isinstance(latency_ms, int) or isinstance(latency_ms, bool):
        return None
    rounded_ms = max(100, min(120_000, round(latency_ms / 100) * 100))
    if rounded_ms < 2_000:
        band = 'fast'
    elif rounded_ms < 8_000:
        band = 'moderate'
    else:
        band = 'slow'
    return {
        'probe_latency_ms': rounded_ms,
        'latency_band': band,
        'sample': 'synthetic_1_token',
    }


def _preferred_model_id(models):
    ids = {model['id'] for model in models}
    if DEFAULT_MODEL_ID in ids and MODEL_BY_ID[DEFAULT_MODEL_ID]['recommended']:
        return DEFAULT_MODEL_ID
    recommended = next((model['id'] for model in models if model['recommended']), None)
    return recommended or (models[0]['id'] if models else None)


def _available_default_model():
    down = unavailable_model_ids()
    return _preferred_model_id([model for model in NVIDIA_MODELS if model['id'] not in down])


def _unavailable_model_response():
    return Response(
        {'error': 'This model is currently unavailable. Choose another model.'},
        status=status.HTTP_409_CONFLICT,
    )


@api_view(['GET'])
@permission_classes([AllowAny])
def health(request):
    return Response({'status': 'ok'})


@api_view(['GET', 'POST'])
@ratelimit(key='user', method='GET', rate='120/m', block=False)
@ratelimit(key='user', method='POST', rate='20/m', block=False)
def conversations(request):
    if request.method == 'GET':
        if (r := _rate_limited(request)): return r
        view = (request.query_params.get('view') or 'active').strip().lower()
        if view not in {'active', 'archived', 'all'}:
            return Response(
                {'error': 'view must be active, archived, or all'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        q = (request.query_params.get('q') or '').strip()
        if len(q) > 200:
            return Response(
                {'error': 'q must be at most 200 characters'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        paginated = request.query_params.get('include_counts') == '1'
        if request.query_params.get('cursor') and not paginated:
            return Response(
                {'error': 'cursor requires include_counts=1'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        raw_limit = request.query_params.get('limit', '30')
        try:
            page_size = int(raw_limit)
        except (TypeError, ValueError):
            return Response({'error': 'limit must be an integer'}, status=status.HTTP_400_BAD_REQUEST)
        if not 1 <= page_size <= 50:
            return Response(
                {'error': 'limit must be between 1 and 50'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        owned = Conversation.objects.filter(user=request.user)
        counts = {
            'active': owned.filter(archived_at__isnull=True).count(),
            'archived': owned.filter(archived_at__isnull=False).count(),
        }
        qs = owned
        if view == 'active':
            qs = qs.filter(archived_at__isnull=True)
        elif view == 'archived':
            qs = qs.filter(archived_at__isnull=False)
        if q:
            message_matches = Message.objects.filter(
                conversation_id=OuterRef('pk'),
                content__icontains=q,
            )
            qs = qs.filter(Q(title__icontains=q) | Exists(message_matches))
        qs = qs.annotate(message_count=Count('messages')).order_by(
            '-is_pinned', '-updated_at', '-id',
        )

        cursor_token = request.query_params.get('cursor')
        if cursor_token:
            if len(cursor_token) > 1000:
                return Response({'error': 'Invalid or expired cursor'}, status=status.HTTP_400_BAD_REQUEST)
            try:
                cursor = signing.loads(
                    cursor_token,
                    salt='chat.conversation.cursor.v1',
                    max_age=24 * 60 * 60,
                )
                cursor_time = parse_datetime(cursor['updated_at'])
                valid_cursor = (
                    isinstance(cursor, dict)
                    and cursor.get('user_id') == request.user.pk
                    and cursor.get('view') == view
                    and cursor.get('query_hash') == hashlib.sha256(q.encode()).hexdigest()[:20]
                    and isinstance(cursor.get('is_pinned'), bool)
                    and isinstance(cursor.get('id'), int)
                    and not isinstance(cursor.get('id'), bool)
                    and cursor['id'] > 0
                    and cursor_time is not None
                    and timezone.is_aware(cursor_time)
                )
                if not valid_cursor:
                    raise signing.BadSignature
            except (KeyError, TypeError, ValueError, signing.BadSignature):
                return Response(
                    {'error': 'Invalid or expired cursor'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            same_pin_older = Q(is_pinned=cursor['is_pinned']) & (
                Q(updated_at__lt=cursor_time)
                | Q(updated_at=cursor_time, id__lt=cursor['id'])
            )
            if cursor['is_pinned']:
                qs = qs.filter(Q(is_pinned=False) | same_pin_older)
            else:
                qs = qs.filter(same_pin_older)

        fetch_size = page_size if paginated else 100
        page = list(qs[:fetch_size + 1])
        has_more = len(page) > fetch_size
        page = page[:fetch_size]
        results = ConversationListSerializer(page, many=True).data
        if paginated:
            next_cursor = None
            if has_more and page:
                last = page[-1]
                next_cursor = signing.dumps({
                    'user_id': request.user.pk,
                    'view': view,
                    'query_hash': hashlib.sha256(q.encode()).hexdigest()[:20],
                    'is_pinned': last.is_pinned,
                    'updated_at': last.updated_at.isoformat(),
                    'id': last.pk,
                }, salt='chat.conversation.cursor.v1')
            return Response({
                'results': results,
                'counts': counts,
                'next_cursor': next_cursor,
            })
        return Response(results)

    if (r := _rate_limited(request)): return r
    title = (request.data.get('title') or 'New Chat').strip()[:200] or 'New Chat'
    requested_model = request.data.get('model_id')
    model_id = requested_model or _available_default_model()
    if model_id is None:
        return Response({'error': 'No chat models are currently available.'}, status=503)
    if model_id not in MODEL_IDS:
        return Response({'error': f'Unknown model_id: {model_id}'}, status=status.HTTP_400_BAD_REQUEST)
    if requested_model and model_id in unavailable_model_ids():
        return _unavailable_model_response()
    convo = Conversation.objects.create(user=request.user, title=title, model_id=model_id)
    return Response(ConversationDetailSerializer(convo).data, status=status.HTTP_201_CREATED)


MAX_SYSTEM_PROMPT_CHARS = 4000


@api_view(['GET', 'DELETE', 'PATCH'])
def conversation_detail(request, pk):
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    if request.method == 'GET':
        return Response(ConversationDetailSerializer(convo).data)
    if request.method == 'DELETE':
        convo.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    title = request.data.get('title')
    model_id = request.data.get('model_id')
    has_archive = 'archived' in request.data
    has_pin = 'is_pinned' in request.data
    requested_archive = request.data.get('archived')
    requested_pin = request.data.get('is_pinned')
    if has_archive and not isinstance(requested_archive, bool):
        return Response({'error': 'archived must be a boolean'}, status=status.HTTP_400_BAD_REQUEST)
    if has_pin and not isinstance(requested_pin, bool):
        return Response({'error': 'is_pinned must be a boolean'}, status=status.HTTP_400_BAD_REQUEST)
    will_be_archived = (has_archive and requested_archive) or (
        not has_archive and convo.archived_at is not None
    )
    if requested_pin is True and will_be_archived:
        return Response(
            {'error': 'Restore the conversation before pinning it.'},
            status=status.HTTP_409_CONFLICT,
        )
    if title is not None:
        convo.title = title.strip()[:200] or convo.title
    if model_id is not None:
        if model_id not in MODEL_IDS:
            return Response({'error': f'Unknown model_id: {model_id}'}, status=status.HTTP_400_BAD_REQUEST)
        if model_id in unavailable_model_ids():
            return _unavailable_model_response()
        convo.model_id = model_id
    if 'system_prompt' in request.data:
        sp = (request.data.get('system_prompt') or '').strip()
        if len(sp) > MAX_SYSTEM_PROMPT_CHARS:
            return Response({'error': f'System prompt too long (max {MAX_SYSTEM_PROMPT_CHARS} chars).'}, status=400)
        convo.system_prompt = sp
    if 'temperature' in request.data:
        try:
            temp = float(request.data.get('temperature'))
        except (TypeError, ValueError):
            return Response({'error': 'temperature must be a number'}, status=400)
        if not (0.0 <= temp <= 2.0):
            return Response({'error': 'temperature must be between 0 and 2'}, status=400)
        convo.temperature = temp
    if 'max_tokens' in request.data:
        try:
            mt = int(request.data.get('max_tokens'))
        except (TypeError, ValueError):
            return Response({'error': 'max_tokens must be an integer'}, status=400)
        if not (64 <= mt <= 8192):
            return Response({'error': 'max_tokens must be between 64 and 8192'}, status=400)
        convo.max_tokens = mt
    if has_archive:
        convo.archived_at = timezone.now() if requested_archive else None
        if requested_archive:
            convo.is_pinned = False
    if has_pin:
        convo.is_pinned = requested_pin
    convo.save()
    return Response(ConversationDetailSerializer(convo).data)


@api_view(['GET'])
def list_attachments(request):
    qs = Attachment.objects.filter(user=request.user)
    kind = request.query_params.get('kind')
    if kind:
        qs = qs.filter(kind=kind)
    return Response(AttachmentSerializer(qs, many=True).data)


@api_view(['GET'])
def account_usage(request):
    files = Attachment.objects.filter(user=request.user).aggregate(bytes=Sum('size'), count=Count('id'))
    return Response({
        'storage_bytes': files['bytes'] or 0,
        'storage_limit_bytes': settings.MAX_USER_STORAGE,
        'attachments': files['count'],
        'conversations': Conversation.objects.filter(user=request.user).count(),
        'messages': Message.objects.filter(conversation__user=request.user).count(),
        'ai_today': user_usage_snapshot(request.user),
    })


def _attachment_capability_response(request, model_id, issue, response_status=400):
    code, message = issue
    logged_model = model_id if model_id in MODEL_IDS else 'unknown'
    security_log.warning(
        'event=attachment_capability_rejected user_id=%s model=%s code=%s',
        request.user.pk,
        logged_model,
        code,
    )
    return Response({
        'error': message,
        'code': code,
        'model_id': model_id,
        'capabilities': model_capabilities(model_id),
    }, status=response_status)


def _attachment_upload_response(attachment, *, deduplicated, response_status):
    data = dict(AttachmentSerializer(attachment).data)
    data['deduplicated'] = deduplicated
    return Response(data, status=response_status)


@api_view(['POST'])
@parser_classes([MultiPartParser])
@ratelimit(key='user', rate='30/m', block=False)
def upload_attachment(request):
    if (r := _rate_limited(request)): return r
    f = request.FILES.get('file')
    if not f:
        return Response({'error': 'file is required'}, status=400)
    if f.size > settings.MAX_ATTACHMENT_SIZE:
        return Response({'error': f'File too large. Max {settings.MAX_ATTACHMENT_SIZE // (1024 * 1024)}MB.'}, status=413)

    mime = detect_mime(f)
    kind = kind_for_mime(mime)
    if kind is None:
        return Response({'error': f'Unsupported file type: {mime}. Allowed: images (jpg/png/webp/gif), pdf, txt, md, docx.'}, status=415)

    model_id = (request.data.get('model_id') or '').strip()
    if model_id:
        if model_id not in MODEL_IDS:
            return _attachment_capability_response(
                request,
                model_id[:120],
                ('unknown_model', 'The selected model is not in the catalog.'),
            )
        if model_id in unavailable_model_ids():
            return _unavailable_model_response()
        issue = attachment_capability_issue(model_id, kind, mime, f.size)
        if issue:
            return _attachment_capability_response(request, model_id, issue)

    content_hash = content_fingerprint(f, request.user.pk)
    duplicate = Attachment.objects.filter(
        user=request.user,
        message__isnull=True,
        content_sha256=content_hash,
    ).first()
    if duplicate:
        return _attachment_upload_response(duplicate, deduplicated=True, response_status=200)

    used = Attachment.objects.filter(user=request.user).aggregate(total=Sum('size'))['total'] or 0
    if used + f.size > settings.MAX_USER_STORAGE:
        return Response({'error': 'Storage quota exceeded.'}, status=413)
    extracted = extract_text(f, mime) if kind == 'document' else ''
    if kind == 'document' and not extracted.strip():
        return _attachment_capability_response(
            request,
            model_id or 'not-selected',
            (
                'document_text_unavailable',
                (
                    'No readable text could be extracted from this document. Try TXT, Markdown, '
                    'or a text-based PDF/DOCX.'
                ),
            ),
            response_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    safe_name = re.sub(r'[^A-Za-z0-9._-]+', '_', os.path.basename(f.name or 'file'))[:120] or 'file'
    # The storage path has a 100-character limit; keep user-facing names separate.
    f.name = secrets.token_hex(12) + Path(safe_name).suffix.lower()

    # Race-free quota: lock the user row, recompute usage inside the lock, then
    # commit the new attachment. Two parallel uploads serialise here.
    User = get_user_model()
    try:
        with transaction.atomic():
            User.objects.select_for_update().filter(pk=request.user.pk).first()
            duplicate = Attachment.objects.filter(
                user=request.user,
                message__isnull=True,
                content_sha256=content_hash,
            ).first()
            if duplicate:
                return _attachment_upload_response(duplicate, deduplicated=True, response_status=200)
            used = Attachment.objects.filter(user=request.user).aggregate(total=Sum('size'))['total'] or 0
            if used + f.size > settings.MAX_USER_STORAGE:
                return Response({
                    'error': f'Storage quota exceeded. Limit {settings.MAX_USER_STORAGE // (1024 * 1024)}MB per user.',
                    'used': used, 'limit': settings.MAX_USER_STORAGE,
                }, status=413)
            att = Attachment.objects.create(
                user=request.user,
                file=f,
                original_name=safe_name,
                mime_type=mime,
                size=f.size,
                kind=kind,
                extracted_text=extracted,
                content_sha256=content_hash,
            )
    except Exception:
        log.exception('Upload failed for user_id=%s', request.user.pk)
        return Response({'error': 'Upload failed.'}, status=500)
    return _attachment_upload_response(att, deduplicated=False, response_status=201)


@api_view(['GET'])
@ratelimit(key='user', rate='60/m', block=False)
def attachment_preview(request, pk):
    if (r := _rate_limited(request)): return r
    attachment = get_object_or_404(Attachment, pk=pk, user=request.user)
    if attachment.kind != Attachment.KIND_DOCUMENT:
        return Response({'error': 'Text preview is available only for documents.'}, status=400)
    if not attachment.extracted_text:
        return Response({'error': 'No extracted text is available for this document.'}, status=404)
    limit = settings.ATTACHMENT_PREVIEW_MAX_CHARS
    response = Response({
        'text': attachment.extracted_text[:limit],
        'characters': len(attachment.extracted_text),
        'truncated': len(attachment.extracted_text) > limit,
    })
    response['Cache-Control'] = 'private, no-store'
    response['Pragma'] = 'no-cache'
    return response


@api_view(['DELETE'])
def delete_attachment(request, pk):
    att = get_object_or_404(Attachment, pk=pk, user=request.user)
    if att.message_id is not None:
        return Response({'error': 'Cannot delete an attachment already linked to a message.'}, status=409)
    att.delete()
    return Response(status=204)


@api_view(['GET'])
def download_attachment(request, pk):
    att = get_object_or_404(Attachment, pk=pk, user=request.user)
    try:
        file = att.file.open('rb')
    except (OSError, ValueError):
        raise Http404 from None
    # Only raster images may render inline. Documents always download.
    inline = att.mime_type in settings.ALLOWED_IMAGE_MIMES
    response = FileResponse(file, as_attachment=not inline,
        filename=att.original_name, content_type=att.mime_type if inline else 'application/octet-stream')
    response['X-Content-Type-Options'] = 'nosniff'
    response['Content-Security-Policy'] = "default-src 'none'; sandbox"
    response['Cross-Origin-Resource-Policy'] = 'same-origin'
    return response


def _stream_nvidia(model_id, messages, max_tokens=1024, temperature=0.7):
    """Yield (kind, value) tuples: ('chunk', str), ('usage', dict), ('error', str)."""
    payload = {
        'model': model_id,
        'messages': messages,
        'max_tokens': max_tokens,
        'temperature': temperature,
        'stream': True,
        'stream_options': {'include_usage': True},
    }
    headers = {
        'Authorization': f'Bearer {settings.NVIDIA_API_KEY}',
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
    }
    try:
        with requests.post(settings.NVIDIA_API_URL, json=payload, headers=headers, timeout=180, stream=True) as resp:
            if resp.status_code >= 400:
                log.warning('NVIDIA chat API returned HTTP %s', resp.status_code)
                # A rejected request did not start generation, so release the
                # token reservation instead of treating it as unmetered spend.
                yield ('usage', {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0})
                yield ('error', f'NVIDIA API error ({resp.status_code}). Try again later.')
                return
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
                if isinstance(line, bytes):
                    line = line.decode('utf-8', errors='replace')
                if not line.startswith('data:'):
                    continue
                data = line[5:].strip()
                if data == '[DONE]':
                    return
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                choices = obj.get('choices') or []
                if choices:
                    delta = choices[0].get('delta') or {}
                    chunk = delta.get('content')
                    if chunk:
                        yield ('chunk', chunk)
                if obj.get('usage'):
                    yield ('usage', obj['usage'])
    except requests.RequestException:
        log.warning('NVIDIA chat API request failed', exc_info=True)
        yield ('error', 'NVIDIA API request failed. Try again later.')


def _attachment_data_url(att):
    with att.file.open('rb') as fh:
        b64 = base64.b64encode(fh.read()).decode('ascii')
    mime = att.mime_type or 'image/jpeg'
    return f'data:{mime};base64,{b64}'


def _build_api_message(role, text, attachments):
    """Render a message in OpenAI-compatible multimodal format."""
    doc_blocks = [
        f'[Document: {a.original_name}]\n{a.extracted_text}\n[/Document]'
        for a in attachments if a.kind == Attachment.KIND_DOCUMENT and a.extracted_text
    ]
    full_text = '\n\n'.join(doc_blocks + ([text] if text else [])) if doc_blocks else text

    images = [a for a in attachments if a.kind in (Attachment.KIND_IMAGE, Attachment.KIND_GENERATED)]
    if not images:
        return {'role': role, 'content': full_text or ''}

    parts = []
    if full_text:
        parts.append({'type': 'text', 'text': full_text})
    for a in images:
        parts.append({'type': 'image_url', 'image_url': {'url': _attachment_data_url(a)}})
    return {'role': role, 'content': parts}


def _message_history_cost(message, attachments):
    text_chars = len(message.content or '') + sum(
        len(a.extracted_text or '') for a in attachments if a.kind == Attachment.KIND_DOCUMENT
    )
    image_bytes = sum(
        a.size for a in attachments if a.kind in (Attachment.KIND_IMAGE, Attachment.KIND_GENERATED)
    )
    return attachments, text_chars, image_bytes


def _bounded_history(messages, model_id):
    """Build history while enforcing the selected model's media contract.

    Newest images win when a provider supports fewer images than the conversation
    contains. Text and extracted documents remain available after switching from
    a vision model to a text-only model.
    """
    keep = []
    text_used = image_bytes_used = 0
    capabilities = model_capabilities(model_id) or {'max_images': 0}
    remaining_images = capabilities['max_images']
    for message in reversed(messages[-settings.CHAT_HISTORY_MAX_MESSAGES:]):
        raw_attachments = sorted(message.attachments.all(), key=lambda attachment: attachment.pk)
        documents = [
            attachment for attachment in raw_attachments
            if attachment.kind == Attachment.KIND_DOCUMENT and attachment.extracted_text
        ]
        compatible_images = [
            attachment for attachment in raw_attachments
            if attachment.kind in (Attachment.KIND_IMAGE, Attachment.KIND_GENERATED)
            and attachment_capability_issue(
                model_id, attachment.kind, attachment.mime_type, attachment.size,
            ) is None
        ]
        images = compatible_images[:remaining_images]
        remaining_images -= len(images)
        attachments, text_cost, image_cost = _message_history_cost(
            message, [*documents, *images],
        )
        exceeds = (
            text_used + text_cost > settings.CHAT_HISTORY_MAX_CHARS
            or image_bytes_used + image_cost > settings.CHAT_HISTORY_MAX_IMAGE_BYTES
        )
        if exceeds and keep:
            break
        keep.append((message, attachments))
        text_used += text_cost
        image_bytes_used += image_cost
    keep.reverse()
    return [_build_api_message(m.role, m.content, attachments) for m, attachments in keep]


def _resolve_attachments(user, ids):
    if not ids:
        return []
    if not isinstance(ids, list):
        return None
    if any(not isinstance(i, int) for i in ids):
        return None
    qs = list(Attachment.objects.filter(id__in=ids, user=user, message__isnull=True))
    if len(qs) != len(set(ids)):
        return None
    return qs


def _sse(event):
    return f'data: {json.dumps(event)}\n\n'


def _finalize_provider_usage(user_id, usage_day, token_reservation, usage):
    try:
        outcome = finalize_chat_usage(user_id, usage_day, token_reservation, usage)
    except Exception:
        log.exception('Failed to finalize AI token usage for user_id=%s', user_id)
        return
    if outcome == 'unmetered':
        security_log.warning('event=ai_usage_unmetered user_id=%s', user_id)
    elif outcome == 'overrun':
        security_log.warning('event=ai_token_reservation_exceeded user_id=%s', user_id)


def _save_assistant_reply(convo_id, reply_text, title_snippet=None):
    """Persist an assistant message and touch the conversation (setting the
    title from `title_snippet` if it's still the placeholder)."""
    assistant_msg = Message.objects.create(conversation_id=convo_id, role='assistant', content=reply_text)
    convo_obj = Conversation.objects.get(id=convo_id)
    if title_snippet and convo_obj.title == 'New Chat':
        convo_obj.title = title_snippet[:60] + ('…' if len(title_snippet) > 60 else '')
    convo_obj.save()
    return assistant_msg, convo_obj


@api_view(['POST'])
@ratelimit(key='user', rate='30/m', block=False)
def send_message(request, pk):
    if (r := _rate_limited(request)): return r
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    user_text = (request.data.get('content') or '').strip()
    if len(user_text) > settings.CHAT_MAX_MESSAGE_CHARS:
        return Response(
            {'error': f'Message too long. Max {settings.CHAT_MAX_MESSAGE_CHARS} characters.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    attachment_ids = request.data.get('attachment_ids') or []
    if isinstance(attachment_ids, list) and len(attachment_ids) > settings.CHAT_MAX_ATTACHMENTS_PER_MESSAGE:
        return Response(
            {'error': f'Too many attachments (max {settings.CHAT_MAX_ATTACHMENTS_PER_MESSAGE} per message).'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    attachments = _resolve_attachments(request.user, attachment_ids)
    if attachments is None:
        return Response({'error': 'Invalid attachment_ids — must be your own unlinked attachments.'}, status=400)

    if not user_text and not attachments:
        return Response({'error': 'content or attachments required'}, status=status.HTTP_400_BAD_REQUEST)
    if sum(a.size for a in attachments) > settings.CHAT_MAX_ATTACHMENT_BYTES_PER_MESSAGE:
        return Response({'error': 'Attachments exceed the 20 MB combined message limit.'}, status=400)
    if sum(len(a.extracted_text or '') for a in attachments) > settings.CHAT_MAX_DOCUMENT_CHARS_PER_MESSAGE:
        return Response({'error': 'Documents exceed the combined extracted-text limit.'}, status=400)

    override_model = request.data.get('model_id')
    effective_model = override_model or convo.model_id
    if effective_model not in MODEL_IDS:
        return _unavailable_model_response()
    if effective_model in unavailable_model_ids():
        return _unavailable_model_response()

    for attachment in attachments:
        if attachment.kind == Attachment.KIND_DOCUMENT and not attachment.extracted_text.strip():
            return _attachment_capability_response(
                request,
                effective_model,
                (
                    'document_text_unavailable',
                    (
                        'No readable text is available for one of these documents. Remove it and '
                        'upload a text-based PDF/DOCX, TXT, or Markdown file.'
                    ),
                ),
                response_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )
        issue = attachment_capability_issue(
            effective_model, attachment.kind, attachment.mime_type, attachment.size,
        )
        if issue:
            return _attachment_capability_response(request, effective_model, issue)

    capabilities = model_capabilities(effective_model)
    image_count = sum(
        attachment.kind in (Attachment.KIND_IMAGE, Attachment.KIND_GENERATED)
        for attachment in attachments
    )
    if image_count > capabilities['max_images']:
        return _attachment_capability_response(
            request,
            effective_model,
            (
                'too_many_images_for_model',
                f"This model accepts at most {capabilities['max_images']} image(s) per request.",
            ),
        )

    if override_model and override_model != convo.model_id:
        convo.model_id = override_model
        convo.save(update_fields=['model_id'])

    prompt_characters = len(user_text) + sum(
        len(a.extracted_text or '') for a in attachments if a.kind == Attachment.KIND_DOCUMENT
    )
    usage_day = timezone.localdate()
    token_reservation = max(convo.max_tokens, settings.AI_CHAT_TOKEN_RESERVATION)
    if (r := _reserve_provider_call(
        request,
        'chat',
        prompt_characters,
        token_reservation=token_reservation,
        day=usage_day,
    )):
        return r

    user_msg = Message.objects.create(conversation=convo, role='user', content=user_text)
    for a in attachments:
        a.message = user_msg
        a.save(update_fields=['message'])

    all_msgs = list(convo.messages.order_by('created_at').prefetch_related('attachments'))
    history = _bounded_history(all_msgs, model_id=convo.model_id)
    if convo.system_prompt:
        history.insert(0, {'role': 'system', 'content': convo.system_prompt})

    user_msg_id = user_msg.id
    user_id = request.user.pk
    convo_id = convo.id
    model_id = convo.model_id
    gen_kwargs = {'max_tokens': convo.max_tokens, 'temperature': convo.temperature}
    user_text_snapshot = user_text
    has_attachments = bool(attachments)
    first_att_name = attachments[0].original_name if attachments else None

    title_snippet = user_text_snapshot or (first_att_name if has_attachments else None)

    def event_stream():
        full_text = []
        last_usage = None
        errored = None
        try:
            yield _sse({'user_message': MessageSerializer(user_msg).data})
            for kind, value in _stream_nvidia(model_id, history, **gen_kwargs):
                if kind == 'chunk':
                    full_text.append(value)
                    yield _sse({'chunk': value})
                elif kind == 'usage':
                    last_usage = value
                elif kind == 'error':
                    errored = value
                    break
        except GeneratorExit:
            # Client hit Stop (or dropped). Keep the exchange: persist what the
            # model already produced so a refetch shows the partial reply.
            partial = ''.join(full_text)
            if partial:
                _save_assistant_reply(convo_id, partial, title_snippet)
            else:
                Attachment.objects.filter(message_id=user_msg_id).update(message=None)
                Message.objects.filter(id=user_msg_id).delete()
            log.info('Stream aborted by client for convo=%s (%d chars kept)', convo_id, len(partial))
            raise
        finally:
            _finalize_provider_usage(user_id, usage_day, token_reservation, last_usage)

        if errored is not None:
            log.warning('NVIDIA stream error for convo=%s: %s', convo_id, errored)
            Attachment.objects.filter(message_id=user_msg_id).update(message=None)
            Message.objects.filter(id=user_msg_id).delete()
            yield _sse({'error': errored})
            return

        reply_text = ''.join(full_text)
        if not reply_text:
            Attachment.objects.filter(message_id=user_msg_id).update(message=None)
            Message.objects.filter(id=user_msg_id).delete()
            yield _sse({'error': 'NVIDIA returned an empty response.'})
            return

        assistant_msg, convo_obj = _save_assistant_reply(convo_id, reply_text, title_snippet)

        user_msg_fresh = Message.objects.prefetch_related('attachments').get(id=user_msg_id)
        yield _sse({
            'done': True,
            'user_message': MessageSerializer(user_msg_fresh).data,
            'assistant_message': MessageSerializer(assistant_msg).data,
            'conversation': ConversationListSerializer(convo_obj).data,
            'usage': last_usage or {},
        })

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache, no-transform'
    response['X-Accel-Buffering'] = 'no'
    return response


def _build_history_for(convo, upto_msg_id=None):
    """Return the OpenAI-format message list for `convo`, capped by the same
    rules send_message uses. If `upto_msg_id` is given, only messages up to
    and including that id are considered (useful for regenerate)."""
    msgs = convo.messages.order_by('created_at').prefetch_related('attachments')
    all_msgs = list(msgs)
    if upto_msg_id is not None:
        cutoff = next((i for i, m in enumerate(all_msgs) if m.id == upto_msg_id), None)
        if cutoff is None:
            return []
        all_msgs = all_msgs[:cutoff + 1]
    history = _bounded_history(all_msgs, model_id=convo.model_id)
    if convo.system_prompt:
        history.insert(0, {'role': 'system', 'content': convo.system_prompt})
    return history


@api_view(['PATCH'])
@ratelimit(key='user', rate='30/m', block=False)
def message_detail(request, pk):
    if (r := _rate_limited(request)): return r
    """Edit a user message's content. Does not regenerate — the frontend
    follows up with POST /messages/<pk>/regenerate/ if it wants a new reply."""
    msg = get_object_or_404(Message, pk=pk, conversation__user=request.user)
    if msg.role != 'user':
        return Response({'error': 'Only user messages can be edited.'}, status=400)
    new_content = (request.data.get('content') or '').strip()
    if not new_content:
        return Response({'error': 'content is required'}, status=400)
    if len(new_content) > settings.CHAT_MAX_MESSAGE_CHARS:
        return Response(
            {'error': f'Message too long. Max {settings.CHAT_MAX_MESSAGE_CHARS} characters.'},
            status=400,
        )
    msg.content = new_content
    msg.save(update_fields=['content'])
    return Response(MessageSerializer(msg).data)


@api_view(['POST'])
@ratelimit(key='user', rate='30/m', block=False)
def regenerate_message(request, pk):
    """Re-roll the assistant reply for a message.

    - If `pk` is an assistant message: delete it and any later messages,
      regenerate from the preceding user message.
    - If `pk` is a user message: delete every message after it, regenerate.
    """
    if (r := _rate_limited(request)): return r
    target = get_object_or_404(Message, pk=pk, conversation__user=request.user)
    convo = target.conversation

    msgs = list(convo.messages.order_by('created_at'))
    idx = next(i for i, m in enumerate(msgs) if m.id == target.id)

    if target.role == 'assistant':
        # Find preceding user message
        prev_user = None
        for m in reversed(msgs[:idx]):
            if m.role == 'user':
                prev_user = m
                break
        if prev_user is None:
            return Response({'error': 'No preceding user message to regenerate from.'}, status=400)
        anchor = prev_user
    else:  # user
        anchor = target

    if convo.model_id in unavailable_model_ids():
        return _unavailable_model_response()

    # Check the durable provider budget before destructive truncation.
    usage_day = timezone.localdate()
    token_reservation = max(convo.max_tokens, settings.AI_CHAT_TOKEN_RESERVATION)
    if (r := _reserve_provider_call(
        request,
        'chat',
        len(anchor.content or ''),
        token_reservation=token_reservation,
        day=usage_day,
    )):
        return r
    if target.role == 'assistant':
        Message.objects.filter(conversation=convo, id__gte=target.id).delete()
    else:
        Message.objects.filter(conversation=convo, id__gt=target.id).delete()

    history = _build_history_for(convo, upto_msg_id=anchor.id)
    if not history:
        return Response({'error': 'Nothing to send.'}, status=400)

    convo_id = convo.id
    user_id = request.user.pk
    model_id = convo.model_id
    gen_kwargs = {'max_tokens': convo.max_tokens, 'temperature': convo.temperature}

    def event_stream():
        full_text = []
        last_usage = None
        errored = None
        try:
            for kind, value in _stream_nvidia(model_id, history, **gen_kwargs):
                if kind == 'chunk':
                    full_text.append(value)
                    yield _sse({'chunk': value})
                elif kind == 'usage':
                    last_usage = value
                elif kind == 'error':
                    errored = value
                    break
        except GeneratorExit:
            partial = ''.join(full_text)
            if partial:
                _save_assistant_reply(convo_id, partial)
            log.info('Regenerate aborted by client for convo=%s (%d chars kept)', convo_id, len(partial))
            raise
        finally:
            _finalize_provider_usage(user_id, usage_day, token_reservation, last_usage)

        if errored is not None:
            log.warning('NVIDIA regenerate error for convo=%s: %s', convo_id, errored)
            yield _sse({'error': errored})
            return

        reply_text = ''.join(full_text)
        if not reply_text:
            yield _sse({'error': 'NVIDIA returned an empty response.'})
            return

        assistant_msg, convo_obj = _save_assistant_reply(convo_id, reply_text)
        yield _sse({
            'done': True,
            'assistant_message': MessageSerializer(assistant_msg).data,
            'conversation': ConversationListSerializer(convo_obj).data,
            'usage': last_usage or {},
        })

    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache, no-transform'
    response['X-Accel-Buffering'] = 'no'
    return response


def _slugify(text):
    s = re.sub(r'[^A-Za-z0-9._-]+', '-', text).strip('-')
    return (s or 'conversation')[:60]


@api_view(['GET'])
def export_conversation(request, pk):
    """Return the conversation as Markdown for download."""
    from django.http import HttpResponse
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    msgs = convo.messages.order_by('created_at').prefetch_related('attachments')

    lines = [
        f'# {convo.title}',
        '',
        f'- Model: `{convo.model_id}`',
        f'- Created: {convo.created_at:%Y-%m-%d %H:%M UTC}',
        f'- Exported by: {request.user.username}',
        '',
        '---',
        '',
    ]
    for m in msgs:
        label = 'User' if m.role == 'user' else 'Assistant'
        lines.append(f'## {label} — {m.created_at:%Y-%m-%d %H:%M:%S}')
        lines.append('')
        if m.content:
            lines.append(m.content)
            lines.append('')
        atts = list(m.attachments.all())
        if atts:
            lines.append('**Attachments:**')
            for a in atts:
                lines.append(f'- `{a.original_name}` ({a.kind}, {a.size} bytes)')
            lines.append('')
        lines.append('')

    body = '\n'.join(lines)
    resp = HttpResponse(body, content_type='text/markdown; charset=utf-8')
    resp['Content-Disposition'] = f'attachment; filename="{_slugify(convo.title)}.md"'
    return resp


@api_view(['GET'])
def list_image_models(request):
    return Response({'models': IMAGE_GEN_MODELS, 'default': DEFAULT_IMAGE_GEN_MODEL_ID})


# Total wall-clock we're willing to spend on one generation, including NVCF
# polling. nginx cuts /api/ at 180s, so stay well under that.
IMAGE_GEN_BUDGET_SECONDS = 120
NVCF_POLL_SECONDS = '30'


def _nvcf_generate(url, payload):
    """POST to an NVCF genai endpoint and follow the async flow if needed.

    NVCF holds the connection up to NVCF-POLL-SECONDS, then returns 202 with
    an NVCF-REQID header to poll at /v1/status/<id>. A 504 with
    `Nvcf-Status: errored` means the function itself failed server-side (seen
    when NVIDIA has no capacity for the model) — surface that cleanly instead
    of hanging for minutes.

    Returns (json_dict, None) on success or (None, Response) on failure.
    """
    headers = {
        'Authorization': f'Bearer {settings.NVIDIA_API_KEY}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'NVCF-POLL-SECONDS': NVCF_POLL_SECONDS,
    }
    unavailable = Response(
        {'error': "NVIDIA's image backend is currently unavailable for this model. Try again later."},
        status=status.HTTP_502_BAD_GATEWAY,
    )
    deadline = time.monotonic() + IMAGE_GEN_BUDGET_SECONDS
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=45)
        while resp.status_code == 202:
            reqid = resp.headers.get('NVCF-REQID')
            if not reqid or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', reqid) or time.monotonic() > deadline:
                log.warning('NVIDIA genai polling gave up (reqid=%s)', reqid)
                return None, unavailable
            resp = requests.get(f'{settings.NVIDIA_GENAI_STATUS_BASE}/{reqid}', headers=headers, timeout=45)
    except requests.RequestException:
        log.warning('NVIDIA genai request failed', exc_info=True)
        return None, Response({'error': 'NVIDIA image API request failed. Try again later.'},
                              status=status.HTTP_502_BAD_GATEWAY)

    if resp.status_code == 504 or resp.headers.get('Nvcf-Status') == 'errored':
        log.warning('NVIDIA genai function errored (status=%s, nvcf-status=%s)',
                    resp.status_code, resp.headers.get('Nvcf-Status'))
        return None, unavailable
    if resp.status_code >= 400:
        log.warning('NVIDIA genai returned HTTP %s', resp.status_code)
        return None, Response({'error': f'NVIDIA image API error ({resp.status_code}). Try again later.'},
                              status=status.HTTP_502_BAD_GATEWAY)
    try:
        return resp.json(), None
    except ValueError:
        return None, Response({'error': 'NVIDIA image API returned a non-JSON response'},
                              status=status.HTTP_502_BAD_GATEWAY)


@api_view(['POST'])
@ratelimit(key='user', rate='10/m', block=False)
def generate_image(request):
    if (r := _rate_limited(request)): return r
    prompt = (request.data.get('prompt') or '').strip()
    if not prompt:
        return Response({'error': 'prompt is required'}, status=400)
    if len(prompt) > 2000:
        return Response({'error': 'prompt too long (max 2000 chars)'}, status=400)

    model_id = request.data.get('model_id') or DEFAULT_IMAGE_GEN_MODEL_ID
    if model_id not in IMAGE_GEN_MODEL_IDS:
        return Response({'error': f'Unknown image model: {model_id}'}, status=400)
    spec = next(m for m in IMAGE_GEN_MODELS if m['id'] == model_id)

    try:
        width = int(request.data.get('width') or 1024)
        height = int(request.data.get('height') or 1024)
        steps = int(request.data.get('steps') or spec['default_steps'])
        seed = int(request.data.get('seed') or 0)
    except (TypeError, ValueError):
        return Response({'error': 'width/height/steps/seed must be integers'}, status=400)

    allowed_dims = spec.get('allowed_dims')
    if allowed_dims:
        if width not in allowed_dims or height not in allowed_dims:
            return Response(
                {'error': f'{spec["name"]} only accepts these dimensions: {", ".join(map(str, allowed_dims))}.',
                 'allowed_dims': allowed_dims},
                status=400,
            )
    elif not (256 <= width <= 1536 and 256 <= height <= 1536):
        return Response({'error': 'width and height must be between 256 and 1536'}, status=400)
    if not (1 <= steps <= spec['max_steps']):
        return Response({'error': f'steps must be 1..{spec["max_steps"]} for {spec["name"]}'}, status=400)
    if not (0 <= seed <= 4_294_967_295):
        return Response({'error': 'seed must be between 0 and 4294967295'}, status=400)

    # Coarse pre-check before paying for an NVIDIA call. Atomic check happens after.
    used = Attachment.objects.filter(user=request.user).aggregate(total=Sum('size'))['total'] or 0
    if used >= settings.MAX_USER_STORAGE:
        return Response({'error': 'Storage quota exceeded; delete some attachments first.'}, status=413)
    if (r := _reserve_provider_call(request, 'image', len(prompt))): return r

    payload = {
        'prompt': prompt,
        'width': width,
        'height': height,
        'seed': seed,
        'steps': steps,
    }
    data, err = _nvcf_generate(f'{settings.NVIDIA_GENAI_BASE}/{model_id}', payload)
    if err is not None:
        return err
    b64 = _extract_image_b64(data)
    if not b64:
        log.warning('NVIDIA genai returned no image data (response_type=%s)', type(data).__name__)
        return Response({'error': 'NVIDIA image API returned no image data'},
                        status=status.HTTP_502_BAD_GATEWAY)

    max_encoded = 4 * ((settings.MAX_ATTACHMENT_SIZE + 2) // 3)
    if len(b64) > max_encoded + 8:
        return Response({'error': 'Generated image exceeds storage limit'}, status=502)
    try:
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError):
        return Response({'error': 'Failed to decode generated image'}, status=502)

    if len(raw) > settings.MAX_ATTACHMENT_SIZE:
        return Response({'error': 'Generated image exceeds storage limit'}, status=502)
    if not (len(raw) >= 33 and raw.startswith(b'\x89PNG\r\n\x1a\n') and raw[12:16] == b'IHDR'):
        return Response({'error': 'Generated image failed validation'}, status=502)

    from django.core.files.base import ContentFile
    safe_slug = re.sub(r'[^a-z0-9]+', '-', prompt.lower())[:32].strip('-') or 'image'
    filename = f'{safe_slug}-{secrets.token_hex(4)}.png'
    User = get_user_model()
    try:
        with transaction.atomic():
            User.objects.select_for_update().filter(pk=request.user.pk).first()
            used = Attachment.objects.filter(user=request.user).aggregate(total=Sum('size'))['total'] or 0
            if used + len(raw) > settings.MAX_USER_STORAGE:
                return Response({'error': 'Storage quota exceeded; delete some attachments first.'}, status=413)
            att = Attachment(
                user=request.user,
                original_name=filename,
                mime_type='image/png',
                size=len(raw),
                kind=Attachment.KIND_GENERATED,
            )
            att.file.save(filename, ContentFile(raw), save=True)
    except Exception:
        log.exception('Generated image save failed for user=%s', request.user.pk)
        return Response({'error': 'Failed to save generated image.'}, status=500)

    return Response({
        'attachment': AttachmentSerializer(att).data,
        'model_id': model_id,
        'prompt': prompt,
        'params': {'width': width, 'height': height, 'steps': steps, 'seed': seed},
    }, status=201)


def _extract_image_b64(data):
    """NVIDIA genai responses come in a few shapes — try all."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get('image'), str):
        return data['image']
    artifacts = data.get('artifacts')
    if isinstance(artifacts, list) and artifacts:
        for a in artifacts:
            if isinstance(a, dict) and isinstance(a.get('base64'), str):
                return a['base64']
    images = data.get('images')
    if isinstance(images, list) and images:
        first = images[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict) and isinstance(first.get('b64_json'), str):
            return first['b64_json']
    if isinstance(data.get('b64_json'), str):
        return data['b64_json']
    return None
