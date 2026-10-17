import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import time
import uuid
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
from django.core.files.base import ContentFile
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.db.models import Count, Exists, OuterRef, Q, Sum
from django.db.models.functions import Length
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

from .attachments import (
    DocumentParserError,
    content_fingerprint,
    detect_mime,
    extract_text,
    kind_for_mime,
)
from .malware import INFECTED, MalwareScanError, ping_scanner, scan_attachment
from .model_status import get_status, unavailable_model_ids
from .nvidia_client import (
    ProviderStreamError,
    chat_completion_headers,
    chat_completion_payload,
    iter_sse_data,
)
from .models import (
    Attachment,
    AttachmentUploadAttempt,
    AuthenticatedSession,
    ChatHistoryRetention,
    ChatStorageGate,
    Conversation,
    ConversationGenerationLease,
    DailyAIUsage,
    EmailVerification,
    GenerationRequest,
    Message,
    PasswordReset,
    ProviderDisclosureAcceptance,
    RegistrationInvite,
    TwoFactor,
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
    model_generation_limits,
)
from .provider_disclosure import (
    CURRENT_PROVIDER_DISCLOSURE_VERSION,
    has_current_provider_disclosure,
    provider_disclosure_state,
)
from .registration import hash_invite_code
from .recent_auth import confirm_recent_auth, mark_recent_auth, require_recent_auth
from .security_events import actor_for_request, security_log
from .serializers import (
    AttachmentSerializer,
    ConversationListSerializer,
    ConversationMetadataSerializer,
    MessageSerializer,
)
from .sessions import stamp_session, sync_session_record
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
    payload = {
        'username': request.user.username if request.user.is_authenticated else None,
        'registration_mode': settings.REGISTRATION_MODE,
    }
    if request.user.is_authenticated:
        payload['provider_disclosure'] = provider_disclosure_state(request.user)
    return Response(payload)


def _authenticated_user_payload(user):
    return {
        'username': user.username,
        'provider_disclosure': provider_disclosure_state(user),
    }


def _provider_disclosure_required_response(request):
    if has_current_provider_disclosure(request.user):
        return None
    return Response({
        'error': 'Review how your content is sent to NVIDIA before generating.',
        'code': 'provider_disclosure_required',
        'provider_disclosure': provider_disclosure_state(request.user),
    }, status=status.HTTP_428_PRECONDITION_REQUIRED)


@api_view(['POST'])
@ratelimit(key='user', rate='10/h', block=False)
def accept_provider_disclosure(request):
    if (r := _rate_limited(request)): return r
    version = request.data.get('version')
    if (
        not isinstance(version, int)
        or isinstance(version, bool)
        or version != CURRENT_PROVIDER_DISCLOSURE_VERSION
    ):
        return Response({
            'error': 'Refresh the page and review the current provider disclosure.',
            'code': 'provider_disclosure_version_mismatch',
            'provider_disclosure': provider_disclosure_state(request.user),
        }, status=status.HTTP_409_CONFLICT)

    with transaction.atomic():
        get_user_model().objects.select_for_update().only('pk').get(
            pk=request.user.pk,
        )
        acceptance = ProviderDisclosureAcceptance.objects.select_for_update().filter(
            user=request.user,
        ).first()
        changed = acceptance is None or acceptance.version != version
        if acceptance is None:
            ProviderDisclosureAcceptance.objects.create(
                user=request.user,
                version=version,
            )
        elif changed:
            acceptance.version = version
            acceptance.accepted_at = timezone.now()
            acceptance.save(update_fields=['version', 'accepted_at'])
    if changed:
        security_log.info(
            'event=provider_disclosure_accepted user_id=%s version=%s',
            request.user.pk,
            version,
        )
    return Response({'provider_disclosure': provider_disclosure_state(request.user)})


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
    mark_recent_auth(request)
    return Response(_authenticated_user_payload(user))


@api_view(['POST'])
def auth_logout(request):
    django_logout(request)
    return Response({'ok': True})


@api_view(['POST'])
@ratelimit(key='user', rate='10/h', block=False)
def auth_reauthenticate(request):
    """Refresh the short-lived authorization window for sensitive actions."""
    if (r := _rate_limited(request)): return r
    response = confirm_recent_auth(
        request,
        request.data.get('password') or '',
        request.data.get('code') or '',
    )
    if response is not None:
        return response
    return Response({
        'authenticated': True,
        'valid_for_seconds': settings.RECENT_AUTH_MAX_AGE_SECONDS,
    })


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
    return Response({'verified': True, **_authenticated_user_payload(user)})


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
    mark_recent_auth(request)
    return Response({
        'reset': True,
        'sessions_revoked': revoked,
        **_authenticated_user_payload(user),
    })


@api_view(['POST'])
@ratelimit(key='user', rate='10/h', block=False)
def auth_change_password(request):
    """Change password after fresh strong auth; keep only this session."""
    if (r := _rate_limited(request)): return r
    current = request.data.get('current_password') or ''
    new = request.data.get('new_password') or ''
    response = confirm_recent_auth(request, current, request.data.get('code') or '')
    if response is not None:
        return response
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
    sync_session_record(request)
    mark_recent_auth(request)
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
    response = confirm_recent_auth(request, password, request.data.get('code') or '')
    if response is not None:
        return response

    user = request.user
    user_id = user.pk
    django_logout(request)
    user.delete()
    security_log.warning('event=account_deleted former_user_id=%s', user_id)
    return Response({'deleted': True})


@api_view(['GET'])
def list_models(request):
    runtime_status = get_status()
    down = unavailable_model_ids(runtime_status)
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
        'availability': {
            'state': runtime_status.get('state', 'unverified'),
            'checked_at': runtime_status.get('checked_at'),
            'inconclusive_models': runtime_status.get('inconclusive_models', 0),
            'unverified_models': runtime_status.get('unverified_models', 0),
            'catalog_models': len(NVIDIA_MODELS),
            'available_models': len(models),
            'unavailable_models': len(down),
        },
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
    generation = model_generation_limits(model_id)
    User = get_user_model()
    with transaction.atomic():
        User.objects.select_for_update().only('pk').get(pk=request.user.pk)
        conversation_count = Conversation.objects.filter(user=request.user).count()
        if conversation_count >= settings.CHAT_MAX_CONVERSATIONS_PER_USER:
            security_log.warning(
                'event=chat_object_quota_blocked code=conversations_limit user_id=%s',
                request.user.pk,
            )
            return _chat_object_quota_response(
                'conversations',
                conversation_count,
                settings.CHAT_MAX_CONVERSATIONS_PER_USER,
            )
        convo = Conversation.objects.create(
            user=request.user,
            title=title,
            model_id=model_id,
            temperature=generation['temperature']['default'],
            max_tokens=generation['max_tokens']['default'],
        )
    return Response(_conversation_data(convo), status=status.HTTP_201_CREATED)


MAX_SYSTEM_PROMPT_CHARS = 4000
MESSAGE_PAGE_DEFAULT = 50
MESSAGE_PAGE_MAX = 100
LEGACY_MESSAGE_LIMIT = 200
ATTACHMENT_PAGE_DEFAULT = 30
ATTACHMENT_PAGE_MAX = 50
LEGACY_ATTACHMENT_LIMIT = 100


def _clamp_conversation_generation(convo, model_id=None):
    """Return fields changed to keep persisted settings inside a model contract."""
    generation = model_generation_limits(model_id or convo.model_id)
    temperature = generation['temperature']
    max_tokens = generation['max_tokens']
    bounded_temperature = min(
        max(convo.temperature, temperature['min']), temperature['max'],
    )
    bounded_max_tokens = min(
        max(convo.max_tokens, max_tokens['min']), max_tokens['max'],
    )
    changed = []
    if convo.temperature != bounded_temperature:
        convo.temperature = bounded_temperature
        changed.append('temperature')
    if convo.max_tokens != bounded_max_tokens:
        convo.max_tokens = bounded_max_tokens
        changed.append('max_tokens')
    return changed


def _page_limit(request, *, default, maximum):
    try:
        value = int(request.query_params.get('limit', str(default)))
    except (TypeError, ValueError):
        return None
    return value if 1 <= value <= maximum else None


def _load_signed_cursor(token, *, salt):
    if not token or len(token) > 1000:
        raise signing.BadSignature
    value = signing.loads(token, salt=salt, max_age=24 * 60 * 60)
    if not isinstance(value, dict):
        raise signing.BadSignature
    return value


def _conversation_message_page(convo, user_id, *, limit, cursor_token=None):
    total = convo.messages.count()
    qs = convo.messages.order_by('-created_at', '-id').prefetch_related('attachments')
    if cursor_token:
        cursor = _load_signed_cursor(cursor_token, salt='chat.message.cursor.v1')
        cursor_time = parse_datetime(cursor.get('created_at')) if isinstance(
            cursor.get('created_at'), str,
        ) else None
        valid = (
            cursor.get('user_id') == user_id
            and cursor.get('conversation_id') == convo.pk
            and isinstance(cursor.get('id'), int)
            and not isinstance(cursor.get('id'), bool)
            and cursor['id'] > 0
            and cursor_time is not None
            and timezone.is_aware(cursor_time)
        )
        if not valid:
            raise signing.BadSignature
        qs = qs.filter(
            Q(created_at__lt=cursor_time)
            | Q(created_at=cursor_time, id__lt=cursor['id'])
        )

    page = list(qs[:limit + 1])
    has_older = len(page) > limit
    page = page[:limit]
    older_cursor = None
    if has_older and page:
        oldest = page[-1]
        older_cursor = signing.dumps({
            'user_id': user_id,
            'conversation_id': convo.pk,
            'created_at': oldest.created_at.isoformat(),
            'id': oldest.pk,
        }, salt='chat.message.cursor.v1')
    page.reverse()
    return {
        'results': MessageSerializer(page, many=True).data,
        'count': total,
        'older_cursor': older_cursor,
    }


def _conversation_data(convo, *, message_limit=LEGACY_MESSAGE_LIMIT):
    recent = list(
        convo.messages.order_by('-created_at', '-id')
        .prefetch_related('attachments')[:message_limit]
    )
    recent.reverse()
    data = dict(ConversationMetadataSerializer(convo).data)
    data['messages'] = MessageSerializer(recent, many=True).data
    return data


@api_view(['GET', 'DELETE', 'PATCH'])
@ratelimit(key='user', method='GET', rate='120/m', block=False)
def conversation_detail(request, pk):
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    if request.method == 'GET':
        if (r := _rate_limited(request)): return r
        paginated = request.query_params.get('message_page')
        if paginated is not None and paginated != '1':
            return Response({'error': 'message_page must be 1'}, status=status.HTTP_400_BAD_REQUEST)
        if paginated == '1':
            limit = _page_limit(
                request,
                default=MESSAGE_PAGE_DEFAULT,
                maximum=MESSAGE_PAGE_MAX,
            )
            if limit is None:
                return Response(
                    {'error': f'limit must be between 1 and {MESSAGE_PAGE_MAX}'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            page = _conversation_message_page(convo, request.user.pk, limit=limit)
            data = dict(ConversationMetadataSerializer(convo).data)
            data['messages'] = page.pop('results')
            data['message_page'] = page
            return Response(data)
        return Response(_conversation_data(convo))
    if request.method == 'DELETE':
        with transaction.atomic():
            locked_convo = Conversation.objects.select_for_update().get(
                pk=convo.pk,
                user=request.user,
            )
            if (conflict := _active_generation_conflict_locked(locked_convo.pk)) is not None:
                return conflict
            locked_convo.delete()
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
    generation = model_generation_limits(convo.model_id)
    if 'system_prompt' in request.data:
        sp = (request.data.get('system_prompt') or '').strip()
        if len(sp) > MAX_SYSTEM_PROMPT_CHARS:
            return Response({'error': f'System prompt too long (max {MAX_SYSTEM_PROMPT_CHARS} chars).'}, status=400)
        convo.system_prompt = sp
    if 'temperature' in request.data:
        raw_temperature = request.data.get('temperature')
        try:
            if isinstance(raw_temperature, bool):
                raise ValueError
            temp = float(raw_temperature)
        except (TypeError, ValueError):
            return Response({'error': 'temperature must be a number'}, status=400)
        temp_limits = generation['temperature']
        if not math.isfinite(temp) or not (temp_limits['min'] <= temp <= temp_limits['max']):
            return Response({
                'error': (
                    f"temperature must be between {temp_limits['min']:g} "
                    f"and {temp_limits['max']:g} for this model"
                ),
            }, status=400)
        convo.temperature = temp
    if 'max_tokens' in request.data:
        raw_max_tokens = request.data.get('max_tokens')
        try:
            if isinstance(raw_max_tokens, bool):
                raise ValueError
            mt = int(raw_max_tokens)
        except (TypeError, ValueError):
            return Response({'error': 'max_tokens must be an integer'}, status=400)
        if isinstance(raw_max_tokens, float) and not raw_max_tokens.is_integer():
            return Response({'error': 'max_tokens must be an integer'}, status=400)
        token_limits = generation['max_tokens']
        if not (token_limits['min'] <= mt <= token_limits['max']):
            return Response({
                'error': (
                    f"max_tokens must be between {token_limits['min']} "
                    f"and {token_limits['max']} for this model"
                ),
            }, status=400)
        convo.max_tokens = mt
    _clamp_conversation_generation(convo)
    if has_archive:
        convo.archived_at = timezone.now() if requested_archive else None
        if requested_archive:
            convo.is_pinned = False
    if has_pin:
        convo.is_pinned = requested_pin
    with transaction.atomic():
        locked_convo = Conversation.objects.select_for_update().get(
            pk=convo.pk,
            user=request.user,
        )
        if (conflict := _active_generation_conflict_locked(locked_convo.pk)) is not None:
            return conflict
        for field in (
            'title',
            'model_id',
            'system_prompt',
            'temperature',
            'max_tokens',
            'is_pinned',
            'archived_at',
        ):
            setattr(locked_convo, field, getattr(convo, field))
        locked_convo.save()
        convo = locked_convo
    return Response(_conversation_data(convo))


@api_view(['GET'])
@ratelimit(key='user', method='GET', rate='120/m', block=False)
def list_attachments(request):
    if (r := _rate_limited(request)): return r
    kind = (request.query_params.get('kind') or '').strip()
    valid_kinds = {value for value, _label in Attachment.KIND_CHOICES}
    if kind and kind not in valid_kinds:
        return Response({'error': 'Invalid attachment kind'}, status=status.HTTP_400_BAD_REQUEST)
    paginated = request.query_params.get('include_count') == '1'
    if request.query_params.get('cursor') and not paginated:
        return Response(
            {'error': 'cursor requires include_count=1'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    limit = _page_limit(
        request,
        default=ATTACHMENT_PAGE_DEFAULT,
        maximum=ATTACHMENT_PAGE_MAX,
    )
    if limit is None:
        return Response(
            {'error': f'limit must be between 1 and {ATTACHMENT_PAGE_MAX}'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    qs = Attachment.objects.filter(user=request.user)
    if kind:
        qs = qs.filter(kind=kind)
    total = qs.count() if paginated else None
    qs = qs.order_by('-created_at', '-id')
    cursor_token = request.query_params.get('cursor')
    if cursor_token:
        try:
            cursor = _load_signed_cursor(cursor_token, salt='chat.attachment.cursor.v1')
            cursor_time = parse_datetime(cursor.get('created_at')) if isinstance(
                cursor.get('created_at'), str,
            ) else None
            valid = (
                cursor.get('user_id') == request.user.pk
                and cursor.get('kind') == kind
                and isinstance(cursor.get('id'), int)
                and not isinstance(cursor.get('id'), bool)
                and cursor['id'] > 0
                and cursor_time is not None
                and timezone.is_aware(cursor_time)
            )
            if not valid:
                raise signing.BadSignature
        except (TypeError, ValueError, signing.BadSignature):
            return Response(
                {'error': 'Invalid or expired cursor'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        qs = qs.filter(
            Q(created_at__lt=cursor_time)
            | Q(created_at=cursor_time, id__lt=cursor['id'])
        )

    fetch_size = limit if paginated else LEGACY_ATTACHMENT_LIMIT
    page = list(qs[:fetch_size + 1])
    has_more = len(page) > fetch_size
    page = page[:fetch_size]
    results = AttachmentSerializer(page, many=True).data
    if not paginated:
        return Response(results)

    next_cursor = None
    if has_more and page:
        last = page[-1]
        next_cursor = signing.dumps({
            'user_id': request.user.pk,
            'kind': kind,
            'created_at': last.created_at.isoformat(),
            'id': last.pk,
        }, salt='chat.attachment.cursor.v1')
    return Response({'results': results, 'count': total, 'next_cursor': next_cursor})


@api_view(['GET'])
def account_usage(request):
    files = Attachment.objects.filter(user=request.user).aggregate(bytes=Sum('size'), count=Count('id'))
    conversation_count = Conversation.objects.filter(user=request.user).count()
    message_usage = Message.objects.filter(conversation__user=request.user).aggregate(
        count=Count('id'),
        bytes=Sum('content_bytes'),
    )
    return Response({
        'storage_bytes': files['bytes'] or 0,
        'storage_limit_bytes': settings.MAX_USER_STORAGE,
        'attachments': files['count'],
        'conversations': conversation_count,
        'conversation_limit': settings.CHAT_MAX_CONVERSATIONS_PER_USER,
        'messages': message_usage['count'],
        'message_limit': settings.CHAT_MAX_MESSAGES_PER_USER,
        'message_limit_per_conversation': settings.CHAT_MAX_MESSAGES_PER_CONVERSATION,
        'message_bytes': message_usage['bytes'] or 0,
        'message_bytes_limit': settings.CHAT_MAX_MESSAGE_BYTES_PER_USER,
        'message_bytes_limit_per_conversation': (
            settings.CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION
        ),
        'ai_today': user_usage_snapshot(request.user),
    })


def _chat_retention_payload(retention):
    archived_days = (
        retention.archived_days
        if retention is not None
        else ChatHistoryRetention.KEEP_FOREVER
    )
    return {
        'archived_days': archived_days,
        'choices': [
            {'days': days, 'label': label}
            for days, label in ChatHistoryRetention.DAY_CHOICES
        ],
        'scope': 'archived_inactive_conversations',
    }


@api_view(['GET', 'PATCH'])
@ratelimit(key='user', method='GET', rate='60/m', block=False)
@ratelimit(key='user', method='PATCH', rate='10/h', block=False)
def account_chat_retention(request):
    if (r := _rate_limited(request)): return r
    retention = ChatHistoryRetention.objects.filter(user=request.user).first()
    if request.method == 'GET':
        return Response(_chat_retention_payload(retention))

    archived_days = request.data.get('archived_days')
    allowed_days = {days for days, _label in ChatHistoryRetention.DAY_CHOICES}
    if (
        not isinstance(archived_days, int)
        or isinstance(archived_days, bool)
        or archived_days not in allowed_days
    ):
        return Response({
            'error': 'archived_days must be one of 0, 30, 90, 180, or 365.',
            'code': 'invalid_chat_retention',
        }, status=status.HTTP_400_BAD_REQUEST)

    with transaction.atomic():
        get_user_model().objects.select_for_update().only('pk').get(pk=request.user.pk)
        retention, _created = ChatHistoryRetention.objects.update_or_create(
            user=request.user,
            defaults={'archived_days': archived_days},
        )
    security_log.info(
        'event=chat_retention_changed user_id=%s archived_days=%s',
        request.user.pk,
        archived_days,
    )
    return Response(_chat_retention_payload(retention))


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


def _attachment_upload_response(attachment, *, deduplicated, response_status, replayed=False):
    data = dict(AttachmentSerializer(attachment).data)
    data['deduplicated'] = deduplicated
    data['replayed'] = replayed
    return Response(data, status=response_status)


def _upload_attempt_error(code, message):
    return Response(
        {'error': message, 'code': code},
        status=status.HTTP_409_CONFLICT,
    )


def _upload_attempt_id(request):
    raw = request.data.get('upload_attempt_id')
    if raw in (None, ''):
        return None, None
    if not isinstance(raw, str) or len(raw) > 36:
        return None, Response(
            {'error': 'upload_attempt_id must be a UUID.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    try:
        attempt_id = uuid.UUID(raw)
    except (AttributeError, ValueError):
        return None, Response(
            {'error': 'upload_attempt_id must be a UUID.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    if str(attempt_id) != raw.lower():
        return None, Response(
            {'error': 'upload_attempt_id must use canonical UUID form.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return attempt_id, None


def _attempt_state_response(attempt):
    if attempt.state == AttachmentUploadAttempt.STATE_CANCELED:
        return _upload_attempt_error(
            'upload_canceled',
            'This upload attempt was canceled.',
        )
    if attempt.state == AttachmentUploadAttempt.STATE_COMPLETED:
        if attempt.attachment_id and attempt.attachment:
            return _attachment_upload_response(
                attempt.attachment,
                deduplicated=not attempt.owns_attachment,
                replayed=True,
                response_status=status.HTTP_200_OK,
            )
        return _upload_attempt_error(
            'upload_expired',
            'This upload attempt no longer has an attachment. Retry with a new attempt.',
        )
    return None


def _prepare_upload_attempt(user, attempt_id):
    if attempt_id is None:
        return None
    User = get_user_model()
    with transaction.atomic():
        User.objects.select_for_update().get(pk=user.pk)
        attempt = AttachmentUploadAttempt.objects.select_for_update().filter(pk=attempt_id).first()
        if attempt is None:
            attempt = AttachmentUploadAttempt.objects.create(id=attempt_id, user=user)
        elif attempt.user_id != user.pk:
            return _upload_attempt_error(
                'invalid_upload_attempt',
                'This upload attempt is unavailable.',
            )
        return _attempt_state_response(attempt)


def _complete_upload_attempt(attempt, attachment, *, owns_attachment):
    if attempt is None:
        return
    attempt.state = AttachmentUploadAttempt.STATE_COMPLETED
    attempt.attachment = attachment
    attempt.owns_attachment = owns_attachment
    attempt.save(update_fields=['state', 'attachment', 'owns_attachment', 'updated_at'])


def _scanner_unavailable_response(request, source):
    security_log.error(
        'event=attachment_scanner_unavailable source=%s user_id=%s',
        source,
        request.user.pk,
    )
    response = Response({
        'error': 'File security scanning is temporarily unavailable. Try again later.',
        'code': 'attachment_scanner_unavailable',
    }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    response['Retry-After'] = '60'
    return response


def _parser_unavailable_response(request):
    security_log.error(
        'event=attachment_parser_unavailable user_id=%s',
        request.user.pk,
    )
    response = Response({
        'error': 'Document processing is temporarily unavailable. Try again later.',
        'code': 'attachment_parser_unavailable',
    }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    response['Retry-After'] = '60'
    return response


def _scanner_readiness_response(request, source):
    if not settings.ATTACHMENT_MALWARE_SCAN_REQUIRED:
        return None
    try:
        ping_scanner()
    except MalwareScanError:
        return _scanner_unavailable_response(request, source)
    return None


def _malware_scan_response(request, uploaded_file, source, *, infected_status):
    if not settings.ATTACHMENT_MALWARE_SCAN_REQUIRED:
        return None
    try:
        verdict = scan_attachment(uploaded_file)
    except MalwareScanError:
        return _scanner_unavailable_response(request, source)
    if verdict == INFECTED:
        security_log.warning(
            'event=attachment_malware_rejected source=%s user_id=%s',
            source,
            request.user.pk,
        )
        return Response({
            'error': 'The file was rejected by the security scanner.',
            'code': 'attachment_malware_detected',
        }, status=infected_status)
    return None


@api_view(['POST'])
@parser_classes([MultiPartParser])
@ratelimit(key='user', rate='12/m', block=False)
def upload_attachment(request):
    if (r := _rate_limited(request)): return r
    f = request.FILES.get('file')
    if not f:
        return Response({'error': 'file is required'}, status=400)
    if f.size > settings.MAX_ATTACHMENT_SIZE:
        return Response({'error': f'File too large. Max {settings.MAX_ATTACHMENT_SIZE // (1024 * 1024)}MB.'}, status=413)
    if (response := _malware_scan_response(
        request,
        f,
        'upload',
        infected_status=status.HTTP_422_UNPROCESSABLE_ENTITY,
    )) is not None:
        return response

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

    attempt_id, attempt_error = _upload_attempt_id(request)
    if attempt_error is not None:
        return attempt_error
    attempt_response = _prepare_upload_attempt(request.user, attempt_id)
    if attempt_response is not None:
        return attempt_response

    content_hash = content_fingerprint(f, request.user.pk)
    User = get_user_model()
    with transaction.atomic():
        User.objects.select_for_update().get(pk=request.user.pk)
        attempt = None
        if attempt_id is not None:
            attempt = AttachmentUploadAttempt.objects.select_for_update().select_related(
                'attachment',
            ).get(pk=attempt_id, user=request.user)
            attempt_response = _attempt_state_response(attempt)
            if attempt_response is not None:
                return attempt_response
        duplicate = Attachment.objects.filter(
            user=request.user,
            message__isnull=True,
            content_sha256=content_hash,
        ).first()
        if duplicate:
            _complete_upload_attempt(attempt, duplicate, owns_attachment=False)
            return _attachment_upload_response(
                duplicate,
                deduplicated=True,
                response_status=status.HTTP_200_OK,
            )

    used = Attachment.objects.filter(user=request.user).aggregate(total=Sum('size'))['total'] or 0
    if used + f.size > settings.MAX_USER_STORAGE:
        return Response({'error': 'Storage quota exceeded.'}, status=413)
    try:
        extracted = extract_text(f, mime) if kind == 'document' else ''
    except DocumentParserError:
        return _parser_unavailable_response(request)
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
    try:
        with transaction.atomic():
            User.objects.select_for_update().get(pk=request.user.pk)
            attempt = None
            if attempt_id is not None:
                attempt = AttachmentUploadAttempt.objects.select_for_update().select_related(
                    'attachment',
                ).get(pk=attempt_id, user=request.user)
                attempt_response = _attempt_state_response(attempt)
                if attempt_response is not None:
                    return attempt_response
            duplicate = Attachment.objects.filter(
                user=request.user,
                message__isnull=True,
                content_sha256=content_hash,
            ).first()
            if duplicate:
                _complete_upload_attempt(attempt, duplicate, owns_attachment=False)
                return _attachment_upload_response(
                    duplicate,
                    deduplicated=True,
                    response_status=status.HTTP_200_OK,
                )
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
            _complete_upload_attempt(attempt, att, owns_attachment=True)
    except Exception:
        log.exception('Upload failed for user_id=%s', request.user.pk)
        return Response({'error': 'Upload failed.'}, status=500)
    return _attachment_upload_response(att, deduplicated=False, response_status=201)


@api_view(['DELETE'])
@ratelimit(key='user', rate='60/m', block=False)
def cancel_attachment_upload(request, attempt_id):
    """Cancel an upload before commit or remove the row it just created."""
    if (r := _rate_limited(request)): return r
    User = get_user_model()
    with transaction.atomic():
        User.objects.select_for_update().get(pk=request.user.pk)
        attempt = AttachmentUploadAttempt.objects.select_for_update().filter(pk=attempt_id).first()
        if attempt is None:
            AttachmentUploadAttempt.objects.create(
                id=attempt_id,
                user=request.user,
                state=AttachmentUploadAttempt.STATE_CANCELED,
            )
            return Response(status=status.HTTP_204_NO_CONTENT)
        if attempt.user_id != request.user.pk:
            raise Http404
        if attempt.owns_attachment and attempt.attachment_id:
            attachment = Attachment.objects.select_for_update().filter(
                pk=attempt.attachment_id,
                user=request.user,
            ).first()
            if attachment is not None and attachment.message_id is not None:
                return _upload_attempt_error(
                    'upload_already_linked',
                    'The uploaded file is already linked to a message.',
                )
            if attachment is not None:
                attachment.delete()
        attempt.state = AttachmentUploadAttempt.STATE_CANCELED
        attempt.attachment = None
        attempt.owns_attachment = False
        attempt.save(update_fields=['state', 'attachment', 'owns_attachment', 'updated_at'])
    return Response(status=status.HTTP_204_NO_CONTENT)


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
@ratelimit(key='user', rate='120/h', block=False)
def download_attachment(request, pk):
    if (r := _rate_limited(request)): return r
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
    deadline = time.monotonic() + 480
    payload = chat_completion_payload(
        model_id, messages, max_tokens=max_tokens, temperature=temperature,
    )
    headers = chat_completion_headers(settings.NVIDIA_API_KEY)
    try:
        with requests.post(
            settings.NVIDIA_API_URL,
            json=payload,
            headers=headers,
            timeout=(10, 120),
            stream=True,
            allow_redirects=False,
        ) as resp:
            if resp.status_code >= 400:
                log.warning('NVIDIA chat API returned HTTP %s', resp.status_code)
                # A rejected request did not start generation, so release the
                # token reservation instead of treating it as unmetered spend.
                yield ('usage', {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0})
                yield ('error', f'NVIDIA API error ({resp.status_code}). Try again later.')
                return
            if 300 <= resp.status_code < 400:
                security_log.warning(
                    'event=provider_protocol_rejected kind=chat reason=redirect',
                )
                yield ('error', 'NVIDIA API returned an invalid stream. Try again later.')
                return
            content_type = resp.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
            if content_type != 'text/event-stream':
                log.warning('NVIDIA chat API returned an invalid streaming content type')
                security_log.warning(
                    'event=provider_protocol_rejected kind=chat reason=content_type',
                )
                yield ('error', 'NVIDIA API returned an invalid stream. Try again later.')
                return
            saw_done = False
            for data in iter_sse_data(resp):
                if time.monotonic() > deadline:
                    raise ProviderStreamError('provider stream exceeded its wall-clock limit')
                if data == '[DONE]':
                    saw_done = True
                    break
                try:
                    obj = json.loads(data)
                except json.JSONDecodeError:
                    continue
                if not isinstance(obj, dict):
                    continue
                if 'error' in obj:
                    log.warning('NVIDIA chat API returned a streaming error event')
                    yield ('error', 'NVIDIA API stream failed. Try again later.')
                    return
                choices = obj.get('choices', [])
                if not isinstance(choices, list):
                    raise ProviderStreamError('provider choices were not a list')
                if choices:
                    if not isinstance(choices[0], dict):
                        raise ProviderStreamError('provider choice was not an object')
                    delta = choices[0].get('delta') or {}
                    if not isinstance(delta, dict):
                        raise ProviderStreamError('provider delta was not an object')
                    chunk = delta.get('content')
                    if chunk is not None and not isinstance(chunk, str):
                        raise ProviderStreamError('provider content was not text')
                    if chunk:
                        yield ('chunk', chunk)
                usage = obj.get('usage')
                if usage is not None:
                    if not isinstance(usage, dict):
                        raise ProviderStreamError('provider usage was not an object')
                    if usage:
                        yield ('usage', usage)
            if not saw_done:
                log.warning('NVIDIA chat API stream ended without a completion marker')
                security_log.warning(
                    'event=provider_protocol_rejected kind=chat reason=incomplete',
                )
                yield ('error', 'NVIDIA API stream ended unexpectedly. Try again later.')
    except ProviderStreamError:
        log.warning('NVIDIA chat API stream exceeded bounds or violated framing')
        security_log.warning(
            'event=provider_protocol_rejected kind=chat reason=bounds_or_shape',
        )
        yield ('error', 'NVIDIA API returned an invalid stream. Try again later.')
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


def _resolve_attachments(user, ids, *, for_update=False):
    if not ids:
        return []
    if not isinstance(ids, list):
        return None
    if any(not isinstance(i, int) for i in ids):
        return None
    unique_ids = list(dict.fromkeys(ids))
    qs = Attachment.objects.filter(
        id__in=unique_ids,
        user=user,
        message__isnull=True,
    )
    if for_update:
        qs = qs.select_for_update()
    by_id = {attachment.pk: attachment for attachment in qs}
    if len(by_id) != len(unique_ids):
        return None
    return [by_id[attachment_id] for attachment_id in unique_ids]


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


ZERO_TOKEN_USAGE = {
    'prompt_tokens': 0,
    'completion_tokens': 0,
    'total_tokens': 0,
}


def _generation_conflict_response(retry_after, *, code='generation_in_progress'):
    response = Response({
        'error': 'A response is already being generated for this conversation.',
        'code': code,
    }, status=status.HTTP_409_CONFLICT)
    response['Retry-After'] = str(max(1, retry_after))
    return response


def _parse_generation_idempotency_key(request):
    raw_key = request.headers.get('Idempotency-Key')
    if raw_key is None:
        return uuid.uuid4(), None
    try:
        parsed = uuid.UUID(raw_key)
    except (AttributeError, TypeError, ValueError):
        parsed = None
    if parsed is None or parsed.int == 0 or raw_key != str(parsed):
        return None, Response({
            'error': 'Idempotency-Key must be a canonical, non-zero UUID.',
            'code': 'invalid_idempotency_key',
        }, status=status.HTTP_400_BAD_REQUEST)
    return parsed, None


def _generation_request_fingerprints(payload):
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(',', ':'),
        sort_keys=True,
    ).encode('utf-8')
    fingerprints = []
    for secret in [settings.SECRET_KEY, *settings.SECRET_KEY_FALLBACKS]:
        root = hmac.new(
            str(secret).encode('utf-8'),
            b'aichat-generation-request-v1',
            hashlib.sha256,
        ).digest()
        digest = hmac.new(root, encoded, hashlib.sha256).hexdigest()
        if digest not in fingerprints:
            fingerprints.append(digest)
    return fingerprints


def _idempotency_key_conflict_response():
    return Response({
        'error': 'This Idempotency-Key was already used for a different request.',
        'code': 'idempotency_key_conflict',
    }, status=status.HTTP_409_CONFLICT)


def _generation_request_closed_response(generation_request):
    return Response({
        'error': 'This generation request is closed and cannot be executed again.',
        'code': 'generation_request_closed',
        'generation_state': generation_request.state if generation_request else 'unavailable',
    }, status=status.HTTP_409_CONFLICT)


def _with_idempotency_key(response, key):
    response['Idempotency-Key'] = str(key)
    return response


def _chat_object_quota_response(resource, used, limit):
    return Response({
        'error': f'Your {resource} limit has been reached. Delete older chat data and retry.',
        'code': f'{resource}_limit',
        'used': used,
        'limit': limit,
    }, status=status.HTTP_409_CONFLICT)


def _utf8_size(value):
    return len((value or '').encode('utf-8'))


def _chat_byte_quota_response(scope, used, limit):
    code = f'{scope}_message_bytes_limit'
    if scope == 'global':
        return Response({
            'error': 'The service-wide saved-chat capacity has been reached.',
            'code': code,
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    label = 'conversation' if scope == 'conversation' else 'account'
    return Response({
        'error': f'This {label} has reached its saved-message size limit. Delete older chat data and retry.',
        'code': code,
        'used': used,
        'limit': limit,
    }, status=status.HTTP_409_CONFLICT)


def _chat_message_byte_quota_conflict(user_id, conversation_id, additional_bytes, now):
    """Check actual plus live-reserved UTF-8 bytes while the gate row is locked."""
    if additional_bytes <= 0:
        return None
    message_totals = Message.objects.aggregate(
        global_bytes=Sum('content_bytes'),
        user_bytes=Sum(
            'content_bytes',
            filter=Q(conversation__user_id=user_id),
        ),
        conversation_bytes=Sum(
            'content_bytes',
            filter=Q(conversation_id=conversation_id),
        ),
    )
    live_leases = ConversationGenerationLease.objects.filter(expires_at__gt=now)
    reservation_totals = live_leases.aggregate(
        global_bytes=Sum('reserved_bytes'),
        user_bytes=Sum(
            'reserved_bytes',
            filter=Q(conversation__user_id=user_id),
        ),
        conversation_bytes=Sum(
            'reserved_bytes',
            filter=Q(conversation_id=conversation_id),
        ),
    )
    totals = {
        scope: int(message_totals[f'{scope}_bytes'] or 0)
        + int(reservation_totals[f'{scope}_bytes'] or 0)
        for scope in ('global', 'user', 'conversation')
    }
    limits = {
        'conversation': settings.CHAT_MAX_MESSAGE_BYTES_PER_CONVERSATION,
        'user': settings.CHAT_MAX_MESSAGE_BYTES_PER_USER,
        'global': settings.CHAT_MAX_MESSAGE_BYTES_GLOBAL,
    }
    for scope in ('conversation', 'user', 'global'):
        if totals[scope] + additional_bytes > limits[scope]:
            return _chat_byte_quota_response(scope, totals[scope], limits[scope])
    return None


def _interrupt_generation_request_locked(generation_request, outcome_code, now):
    """Close a stale fenced request and reconcile an uncommitted send."""
    if (
        generation_request.operation == GenerationRequest.OPERATION_SEND
        and generation_request.user_message_id is not None
        and generation_request.assistant_message_id is None
    ):
        Attachment.objects.filter(
            message_id=generation_request.user_message_id,
        ).update(message=None)
        Message.objects.filter(id=generation_request.user_message_id).delete()
    generation_request.state = GenerationRequest.STATE_INTERRUPTED
    generation_request.outcome_code = outcome_code
    generation_request.completed_at = now
    generation_request.updated_at = now
    generation_request.save(update_fields=[
        'state',
        'outcome_code',
        'completed_at',
        'updated_at',
    ])


def _lease_retry_after(lease, now=None):
    now = now or timezone.now()
    return max(1, math.ceil((lease.expires_at - now).total_seconds()))


def _acquire_generation_lease(
    conversation_id,
    *,
    user_id,
    idempotency_key,
    operation,
    request_fingerprints,
    target_message_id=None,
    message_reservation=0,
    requested_message_bytes=0,
    existing_request_expected=False,
):
    """Claim one conversation and create or resolve its durable request."""
    if message_reservation not in {0, 1, 2}:
        raise ValueError('message_reservation must be between 0 and 2')
    if (
        not isinstance(requested_message_bytes, int)
        or isinstance(requested_message_bytes, bool)
        or requested_message_bytes < 0
    ):
        raise ValueError('requested_message_bytes must be a non-negative integer')
    now = timezone.now()
    expires_at = now + timedelta(seconds=settings.CHAT_GENERATION_LEASE_SECONDS)
    token = uuid.uuid4()
    owner_id = Conversation.objects.filter(pk=conversation_id).values_list(
        'user_id',
        flat=True,
    ).first()
    if owner_id is None or owner_id != user_id:
        raise Http404
    User = get_user_model()
    with transaction.atomic():
        # This singleton is the cross-user serialization boundary for the
        # service-wide byte cap. Always lock it before owner/conversation rows.
        ChatStorageGate.objects.select_for_update().get(pk=1)
        # Every user's generation reservation uses the same lock, so sends to
        # different conversations cannot collectively overrun the user quota.
        User.objects.select_for_update().only('pk').get(pk=owner_id)
        locked_conversation = Conversation.objects.select_for_update().only('pk').filter(
            pk=conversation_id,
            user_id=owner_id,
        ).first()
        if locked_conversation is None:
            raise Http404
        lease = ConversationGenerationLease.objects.select_for_update().filter(
            conversation_id=conversation_id,
        ).first()

        generation_request = GenerationRequest.objects.select_for_update().filter(
            user_id=user_id,
            idempotency_key=idempotency_key,
        ).first()
        if generation_request is not None:
            same_request = (
                generation_request.conversation_id == conversation_id
                and generation_request.operation == operation
                and generation_request.target_message_id == target_message_id
                and generation_request.request_fingerprint in request_fingerprints
            )
            if not same_request:
                security_log.warning(
                    'event=generation_idempotency_conflict user_id=%s conversation_id=%s',
                    user_id,
                    conversation_id,
                )
                return None, generation_request, _idempotency_key_conflict_response()
            if generation_request.state in GenerationRequest.REPLAYABLE_STATES:
                return None, generation_request, None
            if generation_request.state in GenerationRequest.TERMINAL_STATES:
                return (
                    None,
                    generation_request,
                    _generation_request_closed_response(generation_request),
                )
            if (
                lease is not None
                and lease.generation_request_id == generation_request.pk
                and lease.expires_at > now
            ):
                return (
                    None,
                    generation_request,
                    _generation_conflict_response(
                        _lease_retry_after(lease, now),
                        code='generation_request_in_progress',
                    ),
                )
            _interrupt_generation_request_locked(
                generation_request,
                'lease_missing_or_expired',
                now,
            )
            security_log.error(
                'event=generation_request_interrupted user_id=%s conversation_id=%s',
                user_id,
                conversation_id,
            )
            return (
                None,
                generation_request,
                _generation_request_closed_response(generation_request),
            )
        if existing_request_expected:
            return None, None, _generation_request_closed_response(None)
        if lease is not None and lease.expires_at > now:
            return None, None, _generation_conflict_response(_lease_retry_after(lease, now))
        byte_reservation = requested_message_bytes
        if operation == GenerationRequest.OPERATION_REGENERATE:
            reservation_target = Message.objects.filter(
                pk=target_message_id,
                conversation_id=conversation_id,
            ).only('id', 'role').first()
            if reservation_target is None:
                raise Http404
            cutoff = (
                {'id__gte': reservation_target.pk}
                if reservation_target.role == 'assistant'
                else {'id__gt': reservation_target.pk}
            )
            reclaimable_bytes = Message.objects.filter(
                conversation_id=conversation_id,
                **cutoff,
            ).aggregate(total=Sum('content_bytes'))['total'] or 0
            byte_reservation = max(0, requested_message_bytes - reclaimable_bytes)
        if message_reservation:
            user_messages = Message.objects.filter(
                conversation__user_id=owner_id,
            ).count()
            reserved_messages = ConversationGenerationLease.objects.filter(
                conversation__user_id=owner_id,
                expires_at__gt=now,
            ).aggregate(total=Sum('reserved_messages'))['total'] or 0
            projected_user_messages = (
                user_messages + reserved_messages + message_reservation
            )
            if projected_user_messages > settings.CHAT_MAX_MESSAGES_PER_USER:
                return None, None, _chat_object_quota_response(
                    'messages',
                    user_messages + reserved_messages,
                    settings.CHAT_MAX_MESSAGES_PER_USER,
                )
            conversation_messages = Message.objects.filter(
                conversation_id=conversation_id,
            ).count()
            if (
                conversation_messages + message_reservation
                > settings.CHAT_MAX_MESSAGES_PER_CONVERSATION
            ):
                return None, None, _chat_object_quota_response(
                    'conversation_messages',
                    conversation_messages,
                    settings.CHAT_MAX_MESSAGES_PER_CONVERSATION,
                )
        byte_conflict = _chat_message_byte_quota_conflict(
            owner_id,
            conversation_id,
            byte_reservation,
            now,
        )
        if byte_conflict is not None:
            return None, None, byte_conflict
        if lease is not None and lease.generation_request_id is not None:
            stale_request = GenerationRequest.objects.select_for_update().filter(
                pk=lease.generation_request_id,
                state__in=GenerationRequest.ACTIVE_STATES,
            ).first()
            if stale_request is not None:
                _interrupt_generation_request_locked(
                    stale_request,
                    'lease_expired',
                    now,
                )
                security_log.error(
                    'event=generation_request_interrupted user_id=%s conversation_id=%s',
                    owner_id,
                    conversation_id,
                )
        generation_request = GenerationRequest.objects.create(
            user_id=user_id,
            conversation_id=conversation_id,
            idempotency_key=idempotency_key,
            operation=operation,
            request_fingerprint=request_fingerprints[0],
            target_message_id=target_message_id,
        )
        if lease is None:
            ConversationGenerationLease.objects.create(
                conversation_id=conversation_id,
                token=token,
                generation_request=generation_request,
                reserved_messages=message_reservation,
                reserved_bytes=byte_reservation,
                expires_at=expires_at,
            )
        else:
            lease.token = token
            lease.generation_request = generation_request
            lease.reserved_messages = message_reservation
            lease.reserved_bytes = byte_reservation
            lease.expires_at = expires_at
            lease.save(update_fields=[
                'token',
                'generation_request',
                'reserved_messages',
                'reserved_bytes',
                'acquired_at',
                'expires_at',
            ])
    return token, generation_request, None


def _release_generation_lease(conversation_id, token):
    ConversationGenerationLease.objects.filter(
        conversation_id=conversation_id,
        token=token,
    ).delete()


def _renew_generation_lease(conversation_id, token, generation_request_id):
    now = timezone.now()
    expires_at = now + timedelta(
        seconds=settings.CHAT_GENERATION_LEASE_SECONDS,
    )
    renewed = ConversationGenerationLease.objects.filter(
        conversation_id=conversation_id,
        token=token,
        generation_request_id=generation_request_id,
        expires_at__gt=now,
    ).update(expires_at=expires_at)
    if renewed:
        GenerationRequest.objects.filter(
            pk=generation_request_id,
            state=GenerationRequest.STATE_STREAMING,
        ).update(updated_at=now)
    return renewed


def _consume_generation_reservation(
    conversation_id,
    token,
    generation_request_id,
    *,
    message_amount=1,
    byte_amount=0,
):
    if message_amount not in {0, 1}:
        raise ValueError('Generation message reservation consumption must be 0 or 1.')
    if (
        not isinstance(byte_amount, int)
        or isinstance(byte_amount, bool)
        or byte_amount < 0
    ):
        raise ValueError('Generation byte reservation consumption must be non-negative.')
    now = timezone.now()
    lease = ConversationGenerationLease.objects.select_for_update().filter(
        conversation_id=conversation_id,
        token=token,
        generation_request_id=generation_request_id,
        expires_at__gt=now,
    ).first()
    if lease is None:
        raise RuntimeError('Generation lease expired or was lost before commit.')
    if lease.reserved_messages < message_amount or lease.reserved_bytes < byte_amount:
        raise RuntimeError('Generation storage reservation was lost.')
    update_fields = []
    if message_amount:
        lease.reserved_messages -= message_amount
        update_fields.append('reserved_messages')
    if byte_amount:
        lease.reserved_bytes -= byte_amount
        update_fields.append('reserved_bytes')
    if update_fields:
        lease.save(update_fields=update_fields)


def _active_generation_conflict_locked(conversation_id):
    """Return a conflict while the caller holds the conversation row lock."""
    now = timezone.now()
    lease = ConversationGenerationLease.objects.filter(
        conversation_id=conversation_id,
        expires_at__gt=now,
    ).first()
    if lease is None:
        return None
    return _generation_conflict_response(_lease_retry_after(lease, now))


class _GenerationLifecycle:
    """Finalize budget accounting and the DB lease exactly once."""

    def __init__(
        self,
        *,
        conversation_id,
        lease_token,
        generation_request_id,
        user_id,
        usage_day,
        token_reservation,
        on_provider_not_started=None,
        on_provider_incomplete=None,
    ):
        self.conversation_id = conversation_id
        self.lease_token = lease_token
        self.generation_request_id = generation_request_id
        self.user_id = user_id
        self.usage_day = usage_day
        self.token_reservation = token_reservation
        self.on_provider_not_started = on_provider_not_started
        self.on_provider_incomplete = on_provider_incomplete
        self.provider_started = False
        self.last_usage = None
        self.closed = False
        self.next_heartbeat = time.monotonic() + max(
            30,
            settings.CHAT_GENERATION_LEASE_SECONDS // 3,
        )

    def start_provider(self):
        now = timezone.now()
        updated = GenerationRequest.objects.filter(
            pk=self.generation_request_id,
            state=GenerationRequest.STATE_QUEUED,
        ).update(
            state=GenerationRequest.STATE_STREAMING,
            updated_at=now,
        )
        if updated != 1:
            raise RuntimeError('Generation request lost its queued state.')
        self.provider_started = True

    def record_usage(self, usage):
        self.last_usage = usage

    def heartbeat(self):
        now = time.monotonic()
        if now < self.next_heartbeat:
            return
        if _renew_generation_lease(
            self.conversation_id,
            self.lease_token,
            self.generation_request_id,
        ) != 1:
            raise RuntimeError('Generation lease was lost while streaming.')
        self.next_heartbeat = now + max(
            30,
            settings.CHAT_GENERATION_LEASE_SECONDS // 3,
        )

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if not self.provider_started and self.on_provider_not_started is not None:
                self.on_provider_not_started()
        except Exception:
            log.exception(
                'Failed to roll back an unstarted generation for convo=%s',
                self.conversation_id,
            )
        if self.provider_started:
            try:
                if self.on_provider_incomplete is not None:
                    self.on_provider_incomplete()
                else:
                    _mark_generation_request_terminal(
                        self.generation_request_id,
                        GenerationRequest.STATE_FAILED,
                        'stream_closed_without_result',
                    )
            except Exception:
                log.exception(
                    'Failed to reconcile an incomplete generation for convo=%s',
                    self.conversation_id,
                )
        try:
            usage = self.last_usage if self.provider_started else ZERO_TOKEN_USAGE
            _finalize_provider_usage(
                self.user_id,
                self.usage_day,
                self.token_reservation,
                usage,
            )
        finally:
            try:
                _release_generation_lease(self.conversation_id, self.lease_token)
            except Exception:
                log.exception(
                    'Failed to release generation lease for convo=%s',
                    self.conversation_id,
                )


class _ManagedGenerationStream:
    """Make response.close() finalize an iterator that was never consumed."""

    def __init__(self, iterator, lifecycle):
        self.iterator = iter(iterator)
        self.lifecycle = lifecycle
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self.iterator)
        except StopIteration:
            self.close()
            raise
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            close = getattr(self.iterator, 'close', None)
            if close is not None:
                close()
        finally:
            self.lifecycle.close()


def _mark_generation_request_terminal(generation_request_id, state, outcome_code):
    if state not in GenerationRequest.TERMINAL_STATES:
        raise ValueError('Generation request terminal state is invalid.')
    now = timezone.now()
    return GenerationRequest.objects.filter(
        pk=generation_request_id,
        state__in=GenerationRequest.ACTIVE_STATES,
    ).update(
        state=state,
        outcome_code=outcome_code,
        completed_at=now,
        updated_at=now,
    )


def _close_pending_send(
    generation_request_id,
    user_message_id,
    state,
    outcome_code,
):
    with transaction.atomic():
        generation_request = GenerationRequest.objects.select_for_update().get(
            pk=generation_request_id,
        )
        if generation_request.state not in GenerationRequest.ACTIVE_STATES:
            return
        if user_message_id is not None:
            Attachment.objects.filter(message_id=user_message_id).update(message=None)
            Message.objects.filter(id=user_message_id).delete()
        now = timezone.now()
        generation_request.state = state
        generation_request.outcome_code = outcome_code
        generation_request.completed_at = now
        generation_request.updated_at = now
        generation_request.save(update_fields=[
            'state',
            'outcome_code',
            'completed_at',
            'updated_at',
        ])


def _save_assistant_reply(
    convo_id,
    reply_text,
    title_snippet=None,
    *,
    user_id,
    lease_token,
    generation_request_id,
    terminal_state=GenerationRequest.STATE_COMPLETED,
    outcome_code='completed',
):
    """Persist an assistant message and touch the conversation (setting the
    title from `title_snippet` if it's still the placeholder)."""
    User = get_user_model()
    with transaction.atomic():
        ChatStorageGate.objects.select_for_update().get(pk=1)
        User.objects.select_for_update().only('pk').get(pk=user_id)
        convo_obj = Conversation.objects.select_for_update().get(
            id=convo_id,
            user_id=user_id,
        )
        assistant_msg = Message.objects.create(
            conversation_id=convo_id,
            role='assistant',
            content=reply_text,
        )
        _consume_generation_reservation(
            convo_id,
            lease_token,
            generation_request_id,
            byte_amount=_utf8_size(reply_text),
        )
        now = timezone.now()
        updated = GenerationRequest.objects.filter(
            pk=generation_request_id,
            user_id=user_id,
            conversation_id=convo_id,
            state__in=GenerationRequest.ACTIVE_STATES,
        ).update(
            state=terminal_state,
            assistant_message=assistant_msg,
            outcome_code=outcome_code,
            completed_at=now,
            updated_at=now,
        )
        if updated != 1:
            raise RuntimeError('Generation request was lost before reply commit.')
        if title_snippet and convo_obj.title == 'New Chat':
            convo_obj.title = title_snippet[:60] + ('…' if len(title_snippet) > 60 else '')
        convo_obj.save()
    return assistant_msg, convo_obj


def _replace_regenerated_reply(
    convo_id,
    target_id,
    target_role,
    anchor_id,
    reply_text,
    *,
    user_id,
    lease_token,
    generation_request_id,
    consumes_reservation,
    terminal_state=GenerationRequest.STATE_COMPLETED,
    outcome_code='completed',
):
    """Commit a regenerated branch only after replacement text exists."""
    with transaction.atomic():
        ChatStorageGate.objects.select_for_update().get(pk=1)
        get_user_model().objects.select_for_update().only('pk').get(pk=user_id)
        convo_obj = Conversation.objects.select_for_update().get(
            pk=convo_id,
            user_id=user_id,
        )
        if not Message.objects.filter(
            pk=anchor_id,
            conversation_id=convo_id,
            role='user',
        ).exists():
            raise Message.DoesNotExist('Regeneration anchor disappeared.')
        cutoff = {'id__gte': target_id} if target_role == 'assistant' else {'id__gt': target_id}
        replaced = Message.objects.filter(conversation_id=convo_id, **cutoff)
        replaced_bytes = replaced.aggregate(total=Sum('content_bytes'))['total'] or 0
        replaced.delete()
        assistant_msg = Message.objects.create(
            conversation_id=convo_id,
            role='assistant',
            content=reply_text,
        )
        # Validate the lease even when this replacement does not consume a new
        # message slot. An expired worker must never be able to resurrect and
        # overwrite a newer branch merely because its reservation was zero.
        _consume_generation_reservation(
            convo_id,
            lease_token,
            generation_request_id,
            message_amount=int(consumes_reservation),
            byte_amount=max(0, _utf8_size(reply_text) - replaced_bytes),
        )
        now = timezone.now()
        updated = GenerationRequest.objects.filter(
            pk=generation_request_id,
            user_id=user_id,
            conversation_id=convo_id,
            state__in=GenerationRequest.ACTIVE_STATES,
        ).update(
            state=terminal_state,
            assistant_message=assistant_msg,
            outcome_code=outcome_code,
            completed_at=now,
            updated_at=now,
        )
        if updated != 1:
            raise RuntimeError('Generation request was lost before replacement commit.')
        convo_obj.save()
    return assistant_msg, convo_obj


def _generation_replay_response(generation_request):
    generation_request = GenerationRequest.objects.select_related(
        'conversation',
        'user_message',
        'assistant_message',
    ).filter(pk=generation_request.pk).first()
    if generation_request is None or generation_request.assistant_message_id is None:
        return _generation_request_closed_response(generation_request)
    event = {
        'done': True,
        'replayed': True,
        'generation_state': generation_request.state,
        'assistant_message': MessageSerializer(
            generation_request.assistant_message,
        ).data,
        'conversation': ConversationListSerializer(
            generation_request.conversation,
        ).data,
        'usage': {},
    }
    if generation_request.operation == GenerationRequest.OPERATION_SEND:
        if generation_request.user_message_id is None:
            return _generation_request_closed_response(generation_request)
        event['user_message'] = MessageSerializer(generation_request.user_message).data
    security_log.info(
        'event=generation_request_replayed user_id=%s conversation_id=%s',
        generation_request.user_id,
        generation_request.conversation_id,
    )
    response = StreamingHttpResponse(
        iter([_sse(event)]),
        content_type='text/event-stream',
    )
    response['Cache-Control'] = 'no-cache, no-transform'
    response['X-Accel-Buffering'] = 'no'
    return response


@api_view(['GET', 'POST'])
@ratelimit(key='user', method='GET', rate='120/m', block=False)
@ratelimit(key='user', method='POST', rate='30/m', block=False)
def send_message(request, pk):
    if (r := _rate_limited(request)): return r
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    if request.method == 'GET':
        limit = _page_limit(
            request,
            default=MESSAGE_PAGE_DEFAULT,
            maximum=MESSAGE_PAGE_MAX,
        )
        if limit is None:
            return Response(
                {'error': f'limit must be between 1 and {MESSAGE_PAGE_MAX}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            page = _conversation_message_page(
                convo,
                request.user.pk,
                limit=limit,
                cursor_token=request.query_params.get('cursor'),
            )
        except (TypeError, ValueError, signing.BadSignature):
            return Response(
                {'error': 'Invalid or expired cursor'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return Response(page)

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

    idempotency_key, invalid_key_response = _parse_generation_idempotency_key(request)
    if invalid_key_response is not None:
        return invalid_key_response
    override_model = request.data.get('model_id')
    valid_attachment_ids = (
        isinstance(attachment_ids, list)
        and all(isinstance(attachment_id, int) for attachment_id in attachment_ids)
    )
    if valid_attachment_ids:
        normalized_attachment_ids = list(dict.fromkeys(attachment_ids))
        request_fingerprints = _generation_request_fingerprints({
            'attachment_ids': normalized_attachment_ids,
            'content': user_text,
            'model_id': override_model or '',
            'operation': GenerationRequest.OPERATION_SEND,
        })
        existing_request = GenerationRequest.objects.filter(
            user=request.user,
            idempotency_key=idempotency_key,
        ).first()
        if existing_request is not None:
            lease_token, generation_request, conflict = _acquire_generation_lease(
                convo.id,
                user_id=request.user.pk,
                idempotency_key=idempotency_key,
                operation=GenerationRequest.OPERATION_SEND,
                request_fingerprints=request_fingerprints,
                existing_request_expected=True,
            )
            if conflict is not None:
                return _with_idempotency_key(conflict, idempotency_key)
            if lease_token is None:
                return _with_idempotency_key(
                    _generation_replay_response(generation_request),
                    idempotency_key,
                )
            raise RuntimeError('Existing generation request unexpectedly acquired a new lease.')

    attachments = _resolve_attachments(request.user, attachment_ids)
    if attachments is None:
        return Response({'error': 'Invalid attachment_ids — must be your own unlinked attachments.'}, status=400)

    if not user_text and not attachments:
        return Response({'error': 'content or attachments required'}, status=status.HTTP_400_BAD_REQUEST)
    if sum(a.size for a in attachments) > settings.CHAT_MAX_ATTACHMENT_BYTES_PER_MESSAGE:
        return Response({'error': 'Attachments exceed the 20 MB combined message limit.'}, status=400)
    if sum(len(a.extracted_text or '') for a in attachments) > settings.CHAT_MAX_DOCUMENT_CHARS_PER_MESSAGE:
        return Response({'error': 'Documents exceed the combined extracted-text limit.'}, status=400)

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

    if (response := _provider_disclosure_required_response(request)) is not None:
        return response

    # Invalid attachment shapes have already failed in `_resolve_attachments`.
    # Valid IDs are normalized once so duplicates hash identically on replay.
    request_fingerprints = _generation_request_fingerprints({
        'attachment_ids': normalized_attachment_ids,
        'content': user_text,
        'model_id': override_model or '',
        'operation': GenerationRequest.OPERATION_SEND,
    })
    lease_token, generation_request, conflict = _acquire_generation_lease(
        convo.id,
        user_id=request.user.pk,
        idempotency_key=idempotency_key,
        operation=GenerationRequest.OPERATION_SEND,
        request_fingerprints=request_fingerprints,
        message_reservation=2,
        requested_message_bytes=(
            _utf8_size(user_text) + (4 * settings.CHAT_MAX_ASSISTANT_CHARS)
        ),
    )
    if conflict is not None:
        conflict_code = conflict.data.get('code')
        if conflict_code == 'generation_in_progress':
            security_log.warning(
                'event=generation_conflict operation=send user_id=%s conversation_id=%s',
                request.user.pk,
                convo.id,
            )
        elif conflict_code and conflict_code.endswith('_limit'):
            security_log.warning(
                'event=chat_object_quota_blocked code=%s user_id=%s',
                conflict_code,
                request.user.pk,
            )
        return _with_idempotency_key(conflict, idempotency_key)
    if lease_token is None:
        return _with_idempotency_key(
            _generation_replay_response(generation_request),
            idempotency_key,
        )

    # Apply the selected model and its generation contract while no competing
    # generation can snapshot this conversation.
    try:
        with transaction.atomic():
            convo = Conversation.objects.select_for_update().get(
                pk=convo.pk,
                user=request.user,
            )
            conversation_model_changed = (
                override_model is None and convo.model_id != effective_model
            )
            generation_fields = []
            if not conversation_model_changed and override_model and override_model != convo.model_id:
                convo.model_id = override_model
                generation_fields.append('model_id')
            if not conversation_model_changed:
                generation_fields.extend(_clamp_conversation_generation(convo))
            if not conversation_model_changed and generation_fields:
                convo.save(update_fields=list(dict.fromkeys(generation_fields)))
    except Exception:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_FAILED,
            'conversation_lock_failed',
        )
        _release_generation_lease(convo.id, lease_token)
        raise
    if conversation_model_changed:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_CANCELED,
            'conversation_changed',
        )
        _release_generation_lease(convo.id, lease_token)
        response = Response({
            'error': 'The conversation model changed. Retry the message.',
            'code': 'conversation_changed',
        }, status=status.HTTP_409_CONFLICT)
        return _with_idempotency_key(response, idempotency_key)

    prompt_characters = len(user_text) + sum(
        len(a.extracted_text or '') for a in attachments if a.kind == Attachment.KIND_DOCUMENT
    )
    usage_day = timezone.localdate()
    token_reservation = max(convo.max_tokens, settings.AI_CHAT_TOKEN_RESERVATION)
    try:
        budget_response = _reserve_provider_call(
            request,
            'chat',
            prompt_characters,
            token_reservation=token_reservation,
            day=usage_day,
        )
    except Exception:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_FAILED,
            'budget_reservation_failed',
        )
        _release_generation_lease(convo.id, lease_token)
        raise
    if budget_response is not None:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_CANCELED,
            'budget_blocked',
        )
        _release_generation_lease(convo.id, lease_token)
        return _with_idempotency_key(budget_response, idempotency_key)

    pending = {'user_message_id': None}
    lifecycle = _GenerationLifecycle(
        conversation_id=convo.id,
        lease_token=lease_token,
        generation_request_id=generation_request.pk,
        user_id=request.user.pk,
        usage_day=usage_day,
        token_reservation=token_reservation,
        on_provider_not_started=lambda: _close_pending_send(
            generation_request.pk,
            pending['user_message_id'],
            GenerationRequest.STATE_CANCELED,
            'provider_not_started',
        ),
        on_provider_incomplete=lambda: _close_pending_send(
            generation_request.pk,
            pending['user_message_id'],
            GenerationRequest.STATE_FAILED,
            'stream_closed_without_result',
        ),
    )

    try:
        # The initial capability check is user-friendly; this locked recheck is
        # the security boundary against the same upload being claimed by two
        # requests for different conversations.
        with transaction.atomic():
            ChatStorageGate.objects.select_for_update().get(pk=1)
            get_user_model().objects.select_for_update().only('pk').get(
                pk=request.user.pk,
            )
            Conversation.objects.select_for_update().only('pk').get(pk=convo.pk)
            attachments = _resolve_attachments(
                request.user,
                attachment_ids,
                for_update=True,
            )
            if attachments is None:
                attachment_conflict = True
                user_msg = None
            else:
                attachment_conflict = False
                user_msg = Message.objects.create(
                    conversation=convo,
                    role='user',
                    content=user_text,
                )
                pending['user_message_id'] = user_msg.id
                linked = GenerationRequest.objects.filter(
                    pk=generation_request.pk,
                    state=GenerationRequest.STATE_QUEUED,
                ).update(
                    user_message=user_msg,
                    updated_at=timezone.now(),
                )
                if linked != 1:
                    raise RuntimeError('Generation request was lost before message commit.')
                Attachment.objects.filter(
                    pk__in=[attachment.pk for attachment in attachments],
                ).update(message=user_msg)
                _consume_generation_reservation(
                    convo.pk,
                    lease_token,
                    generation_request.pk,
                    byte_amount=_utf8_size(user_text),
                )
        if attachment_conflict:
            lifecycle.close()
            response = Response({
                'error': 'One or more attachments are no longer available. Upload them again.',
                'code': 'attachment_already_claimed',
            }, status=status.HTTP_409_CONFLICT)
            return _with_idempotency_key(response, idempotency_key)

        all_msgs = list(
            convo.messages.order_by('created_at').prefetch_related('attachments')
        )
        history = _bounded_history(all_msgs, model_id=convo.model_id)
        if convo.system_prompt:
            history.insert(0, {'role': 'system', 'content': convo.system_prompt})
    except Exception:
        lifecycle.close()
        raise

    user_msg_id = user_msg.id
    convo_id = convo.id
    model_id = convo.model_id
    gen_kwargs = {'max_tokens': convo.max_tokens, 'temperature': convo.temperature}
    title_snippet = user_text or (
        attachments[0].original_name if attachments else None
    )

    def event_stream():
        full_text = []
        reply_chars = 0
        errored = None
        try:
            yield _sse({'user_message': MessageSerializer(user_msg).data})
            lifecycle.start_provider()
            for kind, value in _stream_nvidia(model_id, history, **gen_kwargs):
                lifecycle.heartbeat()
                if kind == 'chunk':
                    if reply_chars + len(value) > settings.CHAT_MAX_ASSISTANT_CHARS:
                        errored = 'NVIDIA response exceeded the configured output limit.'
                        break
                    full_text.append(value)
                    reply_chars += len(value)
                    yield _sse({'chunk': value})
                elif kind == 'usage':
                    lifecycle.record_usage(value)
                elif kind == 'error':
                    errored = value
                    break
        except GeneratorExit:
            # Client hit Stop (or dropped). Keep the exchange: persist what the
            # model already produced so a refetch shows the partial reply.
            partial = ''.join(full_text)
            if partial:
                _save_assistant_reply(
                    convo_id,
                    partial,
                    title_snippet,
                    user_id=request.user.pk,
                    lease_token=lease_token,
                    generation_request_id=generation_request.pk,
                    terminal_state=GenerationRequest.STATE_CANCELED,
                    outcome_code='client_disconnected_partial',
                )
            else:
                _close_pending_send(
                    generation_request.pk,
                    user_msg_id,
                    GenerationRequest.STATE_CANCELED,
                    'client_disconnected_empty',
                )
            log.info(
                'Stream aborted by client for convo=%s (%d chars kept)',
                convo_id,
                len(partial),
            )
            raise
        except Exception:
            log.exception('Unexpected NVIDIA stream failure for convo=%s', convo_id)
            _close_pending_send(
                generation_request.pk,
                user_msg_id,
                GenerationRequest.STATE_FAILED,
                'stream_exception',
            )
            yield _sse({'error': 'The response stream failed. Try again later.'})
            return

        if errored is not None:
            log.warning('NVIDIA stream error for convo=%s: %s', convo_id, errored)
            _close_pending_send(
                generation_request.pk,
                user_msg_id,
                GenerationRequest.STATE_FAILED,
                'provider_error',
            )
            yield _sse({'error': errored})
            return

        reply_text = ''.join(full_text)
        if not reply_text:
            _close_pending_send(
                generation_request.pk,
                user_msg_id,
                GenerationRequest.STATE_FAILED,
                'empty_provider_response',
            )
            yield _sse({'error': 'NVIDIA returned an empty response.'})
            return

        assistant_msg, convo_obj = _save_assistant_reply(
            convo_id,
            reply_text,
            title_snippet,
            user_id=request.user.pk,
            lease_token=lease_token,
            generation_request_id=generation_request.pk,
        )
        user_msg_fresh = Message.objects.prefetch_related('attachments').get(
            id=user_msg_id,
        )
        yield _sse({
            'done': True,
            'user_message': MessageSerializer(user_msg_fresh).data,
            'assistant_message': MessageSerializer(assistant_msg).data,
            'conversation': ConversationListSerializer(convo_obj).data,
            'usage': lifecycle.last_usage or {},
        })

    managed_stream = _ManagedGenerationStream(event_stream(), lifecycle)
    response = StreamingHttpResponse(managed_stream, content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache, no-transform'
    response['X-Accel-Buffering'] = 'no'
    return _with_idempotency_key(response, idempotency_key)


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
    with transaction.atomic():
        ChatStorageGate.objects.select_for_update().get(pk=1)
        get_user_model().objects.select_for_update().only('pk').get(pk=request.user.pk)
        Conversation.objects.select_for_update().only('pk').get(
            pk=msg.conversation_id,
            user=request.user,
        )
        if (conflict := _active_generation_conflict_locked(msg.conversation_id)) is not None:
            return conflict
        msg = Message.objects.select_for_update().get(
            pk=msg.pk,
            conversation__user=request.user,
        )
        additional_bytes = max(0, _utf8_size(new_content) - msg.content_bytes)
        byte_conflict = _chat_message_byte_quota_conflict(
            request.user.pk,
            msg.conversation_id,
            additional_bytes,
            timezone.now(),
        )
        if byte_conflict is not None:
            security_log.warning(
                'event=chat_object_quota_blocked code=%s user_id=%s',
                byte_conflict.data['code'],
                request.user.pk,
            )
            return byte_conflict
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
    idempotency_key, invalid_key_response = _parse_generation_idempotency_key(request)
    if invalid_key_response is not None:
        return invalid_key_response
    request_fingerprints = _generation_request_fingerprints({
        'operation': GenerationRequest.OPERATION_REGENERATE,
        'target_message_id': pk,
    })
    existing_request = GenerationRequest.objects.select_related('conversation').filter(
        user=request.user,
        idempotency_key=idempotency_key,
    ).first()
    if existing_request is not None:
        lease_token, generation_request, conflict = _acquire_generation_lease(
            existing_request.conversation_id,
            user_id=request.user.pk,
            idempotency_key=idempotency_key,
            operation=GenerationRequest.OPERATION_REGENERATE,
            request_fingerprints=request_fingerprints,
            target_message_id=pk,
            existing_request_expected=True,
        )
        if conflict is not None:
            return _with_idempotency_key(conflict, idempotency_key)
        if lease_token is None:
            return _with_idempotency_key(
                _generation_replay_response(generation_request),
                idempotency_key,
            )
        raise RuntimeError('Existing generation request unexpectedly acquired a new lease.')

    target = get_object_or_404(Message, pk=pk, conversation__user=request.user)
    convo = target.conversation

    if convo.model_id not in MODEL_IDS or convo.model_id in unavailable_model_ids():
        return _unavailable_model_response()

    if (response := _provider_disclosure_required_response(request)) is not None:
        return response

    # Regenerating a trailing user message adds one row. Replacing an existing
    # branch does not grow storage, so it must remain possible at the quota.
    regeneration_reservation = int(
        target.role == 'user'
        and not Message.objects.filter(
            conversation_id=convo.id,
            id__gt=target.id,
        ).exists()
    )
    lease_token, generation_request, conflict = _acquire_generation_lease(
        convo.id,
        user_id=request.user.pk,
        idempotency_key=idempotency_key,
        operation=GenerationRequest.OPERATION_REGENERATE,
        request_fingerprints=request_fingerprints,
        target_message_id=target.pk,
        message_reservation=regeneration_reservation,
        requested_message_bytes=4 * settings.CHAT_MAX_ASSISTANT_CHARS,
    )
    if conflict is not None:
        conflict_code = conflict.data.get('code')
        if conflict_code == 'generation_in_progress':
            security_log.warning(
                'event=generation_conflict operation=regenerate user_id=%s conversation_id=%s',
                request.user.pk,
                convo.id,
            )
        elif conflict_code and conflict_code.endswith('_limit'):
            security_log.warning(
                'event=chat_object_quota_blocked code=%s user_id=%s',
                conflict_code,
                request.user.pk,
            )
        return _with_idempotency_key(conflict, idempotency_key)
    if lease_token is None:
        return _with_idempotency_key(
            _generation_replay_response(generation_request),
            idempotency_key,
        )

    try:
        with transaction.atomic():
            convo = Conversation.objects.select_for_update().get(
                pk=convo.pk,
                user=request.user,
            )
            target = get_object_or_404(
                Message.objects.select_for_update(),
                pk=pk,
                conversation=convo,
            )
            msgs = list(convo.messages.order_by('created_at'))
            idx = next(i for i, message in enumerate(msgs) if message.id == target.id)
            if target.role == 'assistant':
                anchor = next(
                    (message for message in reversed(msgs[:idx]) if message.role == 'user'),
                    None,
                )
            else:
                anchor = target
            generation_fields = _clamp_conversation_generation(convo)
            if generation_fields:
                convo.save(update_fields=generation_fields)
        if anchor is None:
            _mark_generation_request_terminal(
                generation_request.pk,
                GenerationRequest.STATE_CANCELED,
                'missing_anchor',
            )
            _release_generation_lease(convo.id, lease_token)
            response = Response({
                'error': 'No preceding user message to regenerate from.',
            }, status=status.HTTP_400_BAD_REQUEST)
            return _with_idempotency_key(response, idempotency_key)
        # Snapshot the original branch before any destructive mutation. The old
        # answer remains intact on quota rejection, provider error, or an
        # unconsumed StreamingHttpResponse.
        history = _build_history_for(convo, upto_msg_id=anchor.id)
        if not history:
            _mark_generation_request_terminal(
                generation_request.pk,
                GenerationRequest.STATE_CANCELED,
                'empty_history',
            )
            _release_generation_lease(convo.id, lease_token)
            return _with_idempotency_key(
                Response({'error': 'Nothing to send.'}, status=400),
                idempotency_key,
            )
    except Exception:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_FAILED,
            'conversation_lock_failed',
        )
        _release_generation_lease(convo.id, lease_token)
        raise

    usage_day = timezone.localdate()
    token_reservation = max(convo.max_tokens, settings.AI_CHAT_TOKEN_RESERVATION)
    try:
        budget_response = _reserve_provider_call(
            request,
            'chat',
            len(anchor.content or ''),
            token_reservation=token_reservation,
            day=usage_day,
        )
    except Exception:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_FAILED,
            'budget_reservation_failed',
        )
        _release_generation_lease(convo.id, lease_token)
        raise
    if budget_response is not None:
        _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_CANCELED,
            'budget_blocked',
        )
        _release_generation_lease(convo.id, lease_token)
        return _with_idempotency_key(budget_response, idempotency_key)

    lifecycle = _GenerationLifecycle(
        conversation_id=convo.id,
        lease_token=lease_token,
        generation_request_id=generation_request.pk,
        user_id=request.user.pk,
        usage_day=usage_day,
        token_reservation=token_reservation,
        on_provider_not_started=lambda: _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_CANCELED,
            'provider_not_started',
        ),
        on_provider_incomplete=lambda: _mark_generation_request_terminal(
            generation_request.pk,
            GenerationRequest.STATE_FAILED,
            'stream_closed_without_result',
        ),
    )
    convo_id = convo.id
    model_id = convo.model_id
    target_id = target.id
    target_role = target.role
    anchor_id = anchor.id
    gen_kwargs = {'max_tokens': convo.max_tokens, 'temperature': convo.temperature}

    def persist_replacement(
        text,
        terminal_state=GenerationRequest.STATE_COMPLETED,
        outcome_code='completed',
    ):
        return _replace_regenerated_reply(
            convo_id,
            target_id,
            target_role,
            anchor_id,
            text,
            user_id=request.user.pk,
            lease_token=lease_token,
            generation_request_id=generation_request.pk,
            consumes_reservation=bool(regeneration_reservation),
            terminal_state=terminal_state,
            outcome_code=outcome_code,
        )

    def event_stream():
        full_text = []
        reply_chars = 0
        errored = None
        try:
            lifecycle.start_provider()
            for kind, value in _stream_nvidia(model_id, history, **gen_kwargs):
                lifecycle.heartbeat()
                if kind == 'chunk':
                    if reply_chars + len(value) > settings.CHAT_MAX_ASSISTANT_CHARS:
                        errored = 'NVIDIA response exceeded the configured output limit.'
                        break
                    full_text.append(value)
                    reply_chars += len(value)
                    yield _sse({'chunk': value})
                elif kind == 'usage':
                    lifecycle.record_usage(value)
                elif kind == 'error':
                    errored = value
                    break
        except GeneratorExit:
            partial = ''.join(full_text)
            if partial:
                persist_replacement(
                    partial,
                    GenerationRequest.STATE_CANCELED,
                    'client_disconnected_partial',
                )
            else:
                _mark_generation_request_terminal(
                    generation_request.pk,
                    GenerationRequest.STATE_CANCELED,
                    'client_disconnected_empty',
                )
            log.info(
                'Regenerate aborted by client for convo=%s (%d chars kept)',
                convo_id,
                len(partial),
            )
            raise
        except Exception:
            log.exception('Unexpected NVIDIA regenerate failure for convo=%s', convo_id)
            _mark_generation_request_terminal(
                generation_request.pk,
                GenerationRequest.STATE_FAILED,
                'stream_exception',
            )
            yield _sse({'error': 'The response stream failed. Try again later.'})
            return

        if errored is not None:
            log.warning('NVIDIA regenerate error for convo=%s: %s', convo_id, errored)
            _mark_generation_request_terminal(
                generation_request.pk,
                GenerationRequest.STATE_FAILED,
                'provider_error',
            )
            yield _sse({'error': errored})
            return

        reply_text = ''.join(full_text)
        if not reply_text:
            _mark_generation_request_terminal(
                generation_request.pk,
                GenerationRequest.STATE_FAILED,
                'empty_provider_response',
            )
            yield _sse({'error': 'NVIDIA returned an empty response.'})
            return

        assistant_msg, convo_obj = persist_replacement(reply_text)
        yield _sse({
            'done': True,
            'assistant_message': MessageSerializer(assistant_msg).data,
            'conversation': ConversationListSerializer(convo_obj).data,
            'usage': lifecycle.last_usage or {},
        })

    managed_stream = _ManagedGenerationStream(event_stream(), lifecycle)
    response = StreamingHttpResponse(managed_stream, content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache, no-transform'
    response['X-Accel-Buffering'] = 'no'
    return _with_idempotency_key(response, idempotency_key)


def _slugify(text):
    s = re.sub(r'[^A-Za-z0-9._-]+', '-', text).strip('-')
    return (s or 'conversation')[:60]


def _export_timestamp(value):
    if value is None:
        return None
    return value.isoformat().replace('+00:00', 'Z')


def _export_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(',', ':'),
    ).encode('utf-8')


@api_view(['GET'])
@ratelimit(key='user', rate='2/d', block=False)
def export_account(request):
    """Stream a bounded owner-only JSON export without secrets or file bodies."""
    if (r := _rate_limited(request)): return r
    if (response := require_recent_auth(request)) is not None:
        return response

    user_id = request.user.pk
    conversations = Conversation.objects.filter(user_id=user_id).order_by('created_at', 'id')
    messages = Message.objects.filter(conversation__user_id=user_id).order_by(
        'conversation_id', 'created_at', 'id',
    )
    attachments = Attachment.objects.filter(user_id=user_id).select_related(
        'message__conversation',
    ).order_by('created_at', 'id')
    generation_requests = GenerationRequest.objects.filter(
        user_id=user_id,
        conversation__user_id=user_id,
    ).order_by('created_at', 'id')
    usage_rows = DailyAIUsage.objects.filter(user_id=user_id).order_by('day', 'id')
    sessions = AuthenticatedSession.objects.filter(user_id=user_id).order_by('login_at')

    conversation_stats = conversations.aggregate(
        count=Count('id'),
        title_characters=Sum(Length('title')),
        system_characters=Sum(Length('system_prompt')),
    )
    message_stats = messages.aggregate(
        count=Count('id'),
        bytes=Sum('content_bytes'),
    )
    attachment_stats = attachments.aggregate(
        count=Count('id'),
        name_characters=Sum(Length('original_name')),
        mime_characters=Sum(Length('mime_type')),
    )
    generation_count = generation_requests.count()
    usage_count = usage_rows.count()
    session_stats = sessions.aggregate(
        count=Count('session_id'),
        user_agent_characters=Sum(Length('user_agent')),
        ip_characters=Sum(Length('ip_address')),
    )
    counts = {
        'conversations': conversation_stats['count'],
        'messages': message_stats['count'],
        'attachments': attachment_stats['count'],
        'generation_requests': generation_count,
        'ai_usage_days': usage_count,
        'sessions': session_stats['count'],
    }
    record_count = sum(counts.values())
    export_characters = sum((
        conversation_stats['title_characters'] or 0,
        conversation_stats['system_characters'] or 0,
        attachment_stats['name_characters'] or 0,
        attachment_stats['mime_characters'] or 0,
        session_stats['user_agent_characters'] or 0,
        session_stats['ip_characters'] or 0,
    ))
    # ensure_ascii=False keeps normal UTF-8 compact. Six bytes per stored byte/
    # character safely covers the worst JSON control-character escape, while the
    # per-record allowance covers keys, identifiers and timestamps.
    estimated_bytes = (
        (message_stats['bytes'] or 0) * 6
        + export_characters * 6
        + record_count * 1024
        + 128 * 1024
    )
    if (
        record_count > settings.ACCOUNT_EXPORT_MAX_RECORDS
        or estimated_bytes > settings.ACCOUNT_EXPORT_MAX_BYTES
    ):
        return Response({
            'error': 'This account is too large to export safely in one file.',
            'code': 'account_export_too_large',
            'record_limit': settings.ACCOUNT_EXPORT_MAX_RECORDS,
            'byte_limit': settings.ACCOUNT_EXPORT_MAX_BYTES,
        }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    retention = ChatHistoryRetention.objects.filter(user_id=user_id).values(
        'archived_days', 'updated_at',
    ).first()
    acceptance = ProviderDisclosureAcceptance.objects.filter(user_id=user_id).values(
        'version', 'accepted_at',
    ).first()
    two_factor = TwoFactor.objects.filter(user_id=user_id).values(
        'enabled', 'enrolled_at', 'last_used_at',
    ).first()
    invitation = RegistrationInvite.objects.filter(used_by_id=user_id).values(
        'used_at',
    ).first()
    exported_at = timezone.now()
    prefix = {
        'schema_version': 1,
        'exported_at': _export_timestamp(exported_at),
        'account': {
            'id': user_id,
            'username': request.user.username,
            'email': request.user.email,
            'first_name': request.user.first_name,
            'last_name': request.user.last_name,
            'is_staff': request.user.is_staff,
            'is_active': request.user.is_active,
            'date_joined': _export_timestamp(request.user.date_joined),
            'last_login': _export_timestamp(request.user.last_login),
        },
        'preferences_and_security': {
            'archived_chat_retention_days': retention['archived_days'] if retention else 0,
            'archived_chat_retention_updated_at': (
                _export_timestamp(retention['updated_at']) if retention else None
            ),
            'provider_disclosure': {
                'version': acceptance['version'] if acceptance else None,
                'accepted_at': (
                    _export_timestamp(acceptance['accepted_at']) if acceptance else None
                ),
            },
            'two_factor': {
                'enabled': two_factor['enabled'] if two_factor else False,
                'enrolled_at': (
                    _export_timestamp(two_factor['enrolled_at']) if two_factor else None
                ),
                'last_used_at': (
                    _export_timestamp(two_factor['last_used_at']) if two_factor else None
                ),
            },
            'invitation_redeemed_at': (
                _export_timestamp(invitation['used_at']) if invitation else None
            ),
        },
        'counts': counts,
        'attachment_files_included': False,
    }
    current_session_key = request.session.session_key

    def records(queryset, mapper):
        first = True
        for item in queryset.iterator(chunk_size=100):
            if not first:
                yield b','
            first = False
            yield _export_json(mapper(item))

    def attachment_record(item):
        owner_linked = (
            item.message_id is not None
            and item.message.conversation.user_id == user_id
        )
        return {
            'id': item.pk,
            'message_id': item.message_id if owner_linked else None,
            'conversation_id': item.message.conversation_id if owner_linked else None,
            'original_name': item.original_name,
            'mime_type': item.mime_type,
            'size': item.size,
            'kind': item.kind,
            'created_at': _export_timestamp(item.created_at),
            'file_bytes_included': False,
        }

    def raw_stream():
        encoded_prefix = _export_json(prefix)
        yield encoded_prefix[:-1] + b',"conversations":['
        yield from records(conversations, lambda item: {
            'id': item.pk,
            'title': item.title,
            'model_id': item.model_id,
            'system_prompt': item.system_prompt,
            'temperature': item.temperature,
            'max_tokens': item.max_tokens,
            'is_pinned': item.is_pinned,
            'archived_at': _export_timestamp(item.archived_at),
            'created_at': _export_timestamp(item.created_at),
            'updated_at': _export_timestamp(item.updated_at),
        })
        yield b'],"messages":['
        yield from records(messages, lambda item: {
            'id': item.pk,
            'conversation_id': item.conversation_id,
            'role': item.role,
            'content': item.content,
            'created_at': _export_timestamp(item.created_at),
        })
        yield b'],"attachments":['
        yield from records(attachments, attachment_record)
        yield b'],"generation_requests":['
        yield from records(generation_requests, lambda item: {
            'id': item.pk,
            'conversation_id': item.conversation_id,
            'idempotency_key': str(item.idempotency_key),
            'operation': item.operation,
            'target_message_id': item.target_message_id,
            'state': item.state,
            'user_message_id': item.user_message_id,
            'assistant_message_id': item.assistant_message_id,
            'outcome_code': item.outcome_code,
            'created_at': _export_timestamp(item.created_at),
            'updated_at': _export_timestamp(item.updated_at),
            'completed_at': _export_timestamp(item.completed_at),
        })
        yield b'],"ai_usage_history":['
        yield from records(usage_rows, lambda item: {
            'day': item.day.isoformat(),
            'chat_requests': item.chat_requests,
            'image_requests': item.image_requests,
            'prompt_characters': item.prompt_characters,
            'prompt_tokens': item.prompt_tokens,
            'completion_tokens': item.completion_tokens,
            'reserved_tokens': item.reserved_tokens,
            'unmetered_chat_requests': item.unmetered_chat_requests,
        })
        yield b'],"sessions":['
        yield from records(sessions, lambda item: {
            'current': item.session_id == current_session_key,
            'user_agent': item.user_agent,
            'ip_address': item.ip_address,
            'login_at': _export_timestamp(item.login_at),
            'absolute_expires_at': _export_timestamp(item.absolute_expires_at),
        })
        yield b']}'

    def bounded_stream():
        emitted = 0
        for chunk in raw_stream():
            emitted += len(chunk)
            if emitted > settings.ACCOUNT_EXPORT_MAX_BYTES:
                security_log.error(
                    'event=account_export_bound_exceeded user_id=%s',
                    user_id,
                )
                raise RuntimeError('Account export exceeded its validated byte bound.')
            yield chunk
        security_log.info(
            'event=account_export_completed user_id=%s records=%s bytes=%s',
            user_id,
            record_count,
            emitted,
        )

    response = StreamingHttpResponse(
        bounded_stream(),
        content_type='application/json; charset=utf-8',
    )
    response['Content-Disposition'] = (
        f'attachment; filename="aichat-account-{exported_at:%Y%m%dT%H%M%SZ}.json"'
    )
    response['Cache-Control'] = 'private, no-store'
    response['X-Accel-Buffering'] = 'no'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


@api_view(['GET'])
@ratelimit(key='user', rate='10/h', block=False)
def export_conversation(request, pk):
    """Stream one bounded, owner-scoped conversation as Markdown."""
    if (r := _rate_limited(request)): return r
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    msgs = convo.messages.order_by('created_at').prefetch_related('attachments')
    message_stats = msgs.aggregate(
        count=Count('id'),
        characters=Sum(Length('content')),
    )
    attachment_stats = Attachment.objects.filter(
        message__conversation=convo,
    ).aggregate(
        count=Count('id'),
        name_characters=Sum(Length('original_name')),
    )
    estimated_bytes = (
        (message_stats['characters'] or 0) * 4
        + (attachment_stats['name_characters'] or 0) * 4
        + message_stats['count'] * 256
        + attachment_stats['count'] * 128
        + 1024
    )
    if estimated_bytes > settings.CHAT_MAX_EXPORT_BYTES:
        return Response({
            'error': 'This conversation is too large to export safely.',
            'code': 'export_too_large',
            'limit': settings.CHAT_MAX_EXPORT_BYTES,
        }, status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)

    def markdown_stream():
        yield '\n'.join([
            f'# {convo.title}',
            '',
            f'- Model: `{convo.model_id}`',
            f'- Created: {convo.created_at:%Y-%m-%d %H:%M UTC}',
            f'- Exported by: {request.user.username}',
            '',
            '---',
            '',
        ])
        for message in msgs.iterator(chunk_size=100):
            label = 'User' if message.role == 'user' else 'Assistant'
            lines = [
                f'## {label} — {message.created_at:%Y-%m-%d %H:%M:%S}',
                '',
            ]
            if message.content:
                lines.extend([message.content, ''])
            attachments = list(message.attachments.all())
            if attachments:
                lines.append('**Attachments:**')
                lines.extend(
                    f'- `{attachment.original_name}` ({attachment.kind}, '
                    f'{attachment.size} bytes)'
                    for attachment in attachments
                )
                lines.append('')
            lines.extend(['', ''])
            yield '\n'.join(lines)

    resp = StreamingHttpResponse(
        markdown_stream(),
        content_type='text/markdown; charset=utf-8',
    )
    resp['Content-Disposition'] = f'attachment; filename="{_slugify(convo.title)}.md"'
    resp['Cache-Control'] = 'private, no-store'
    resp['X-Accel-Buffering'] = 'no'
    return resp


@api_view(['GET'])
def list_image_models(request):
    return Response({'models': IMAGE_GEN_MODELS, 'default': DEFAULT_IMAGE_GEN_MODEL_ID})


# Total wall-clock we're willing to spend on one generation, including NVCF
# polling. nginx cuts /api/ at 180s, so stay well under that.
IMAGE_GEN_BUDGET_SECONDS = 120
NVCF_POLL_SECONDS = '30'
IMAGE_PROVIDER_MAX_RESPONSE_BYTES = 16 * 1024 * 1024


def _bounded_provider_json(response):
    raw_length = response.headers.get('Content-Length')
    if raw_length not in (None, ''):
        try:
            declared_length = int(raw_length)
        except (TypeError, ValueError):
            raise ValueError('invalid provider content length') from None
        if not 0 <= declared_length <= IMAGE_PROVIDER_MAX_RESPONSE_BYTES:
            raise ValueError('provider response exceeds byte limit')
    content = bytearray()
    for chunk in response.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        if not isinstance(chunk, bytes):
            raise ValueError('provider response returned invalid bytes')
        content.extend(chunk)
        if len(content) > IMAGE_PROVIDER_MAX_RESPONSE_BYTES:
            raise ValueError('provider response exceeds byte limit')
    return json.loads(content)


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
        resp = requests.post(
            url,
            json=payload,
            headers=headers,
            timeout=(10, 45),
            stream=True,
            allow_redirects=False,
        )
        while resp.status_code == 202:
            reqid = resp.headers.get('NVCF-REQID')
            if not reqid or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', reqid):
                log.warning('NVIDIA genai polling returned an invalid identifier')
                security_log.warning(
                    'event=provider_protocol_rejected kind=image reason=poll_identifier',
                )
                resp.close()
                return None, unavailable
            if time.monotonic() > deadline:
                log.warning('NVIDIA genai polling exceeded its deadline')
                resp.close()
                return None, unavailable
            resp.close()
            resp = requests.get(
                f'{settings.NVIDIA_GENAI_STATUS_BASE}/{reqid}',
                headers=headers,
                timeout=(10, 45),
                stream=True,
                allow_redirects=False,
            )
    except requests.RequestException:
        log.warning('NVIDIA genai request failed', exc_info=True)
        return None, Response({'error': 'NVIDIA image API request failed. Try again later.'},
                              status=status.HTTP_502_BAD_GATEWAY)

    if resp.status_code == 504 or resp.headers.get('Nvcf-Status') == 'errored':
        log.warning('NVIDIA genai function errored (status=%s, nvcf-status=%s)',
                    resp.status_code, resp.headers.get('Nvcf-Status'))
        resp.close()
        return None, unavailable
    if resp.status_code != 200:
        log.warning('NVIDIA genai returned HTTP %s', resp.status_code)
        if 300 <= resp.status_code < 400:
            security_log.warning(
                'event=provider_protocol_rejected kind=image reason=redirect',
            )
        elif resp.status_code < 400:
            security_log.warning(
                'event=provider_protocol_rejected kind=image reason=terminal_status',
            )
        resp.close()
        return None, Response({'error': f'NVIDIA image API error ({resp.status_code}). Try again later.'},
                              status=status.HTTP_502_BAD_GATEWAY)
    try:
        data = _bounded_provider_json(resp)
        if not isinstance(data, dict):
            raise ValueError('provider response was not an object')
        return data, None
    except (UnicodeError, ValueError, json.JSONDecodeError):
        security_log.warning(
            'event=provider_protocol_rejected kind=image reason=bounds_or_shape',
        )
        return None, Response({'error': 'NVIDIA image API returned an invalid response'},
                              status=status.HTTP_502_BAD_GATEWAY)
    finally:
        resp.close()


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

    if (response := _provider_disclosure_required_response(request)) is not None:
        return response
    if (response := _scanner_readiness_response(request, 'provider_image')) is not None:
        return response

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

    image_file = ContentFile(raw)
    if (response := _malware_scan_response(
        request,
        image_file,
        'provider_image',
        infected_status=status.HTTP_502_BAD_GATEWAY,
    )) is not None:
        return response
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
            att.file.save(filename, image_file, save=True)
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
