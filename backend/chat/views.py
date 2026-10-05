import base64
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import secrets
import time
from datetime import timedelta

import requests
from django.http import FileResponse, Http404, StreamingHttpResponse
from django.conf import settings
from django.contrib.auth import (
    authenticate, get_user_model, login as django_login, logout as django_logout,
    update_session_auth_hash,
)
from django.contrib.auth.password_validation import validate_password
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Count, Q, Sum
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes, permission_classes
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .attachments import detect_mime, extract_text, kind_for_mime
from .model_status import get_status, unavailable_model_ids
from .models import Attachment, Conversation, EmailVerification, Message, PasswordReset
from .sessions import stamp_session
from .twofactor import _revoke_user_sessions, login_requires_2fa, verify_for_login
from .models_catalog import (
    DEFAULT_IMAGE_GEN_MODEL_ID,
    DEFAULT_MODEL_ID,
    IMAGE_GEN_MODEL_IDS,
    IMAGE_GEN_MODELS,
    MODEL_IDS,
    NVIDIA_MODELS,
    VISION_MODEL_IDS,
)
from .serializers import (
    AttachmentSerializer,
    ConversationDetailSerializer,
    ConversationListSerializer,
    MessageSerializer,
)

log = logging.getLogger(__name__)


def _rate_limited(request):
    return Response({'error': 'Too many requests. Slow down and try again.'}, status=429) if getattr(request, 'limited', False) else None


@api_view(['GET'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def auth_me(request):
    if request.user.is_authenticated:
        return Response({'username': request.user.username})
    return Response({'username': None})


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
    if login_requires_2fa(user):
        code = (request.data.get('code') or '').strip()
        if not code:
            return Response({'error': 'Two-factor code required.', 'two_factor_required': True},
                            status=status.HTTP_401_UNAUTHORIZED)
        if not verify_for_login(user, code):
            return Response({'error': 'Invalid 2FA code.', 'two_factor_required': True},
                            status=status.HTTP_401_UNAUTHORIZED)
    django_login(request, user)
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


def _hash_code(code: str) -> str:
    pepper = settings.SECRET_KEY.encode()
    return hmac.new(pepper, code.encode(), hashlib.sha256).hexdigest()


def _generate_code() -> str:
    return f'{secrets.randbelow(1_000_000):06d}'


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

    User = get_user_model()
    if User.objects.filter(username__iexact=username).exists():
        return Response({'error': 'Username already taken.'}, status=409)
    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'An account with this email already exists.'}, status=409)

    # Honeypot fires only after the request would have succeeded. Bots that
    # fill every field still get the same 201 a real user gets, but no row
    # is written and no email goes out.
    if honeypot:
        log.info('Honeypot tripped on register from %s', request.META.get('REMOTE_ADDR'))
        return Response({
            'message': 'Account created. Check your email for the 6-digit code.',
            'email': email,
            'resend_available_in': RESEND_COOLDOWN_SECONDS,
        }, status=201)

    user = User(username=username, email=email, is_active=False)
    try:
        validate_password(password, user)
    except ValidationError as e:
        return Response({'error': ' '.join(e.messages)}, status=400)
    user.set_password(password)
    user.save()

    try:
        _issue_new_code(user)
    except Exception:
        log.exception('Failed to send verification email to %s', email)
        user.delete()
        return Response({'error': 'Failed to send verification email. Try again later.'}, status=502)

    return Response({
        'message': 'Account created. Check your email for the 6-digit code.',
        'email': user.email,
        'resend_available_in': RESEND_COOLDOWN_SECONDS,
    }, status=201)


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
        return Response({'error': 'Invalid email or code.'}, status=400)
    if user.is_active:
        return Response({'error': 'Invalid email or code.'}, status=400)

    ev = EmailVerification.objects.filter(user=user).first()
    if ev is None:
        return Response({'error': 'No active verification. Request a new code.'}, status=400)
    if ev.expires_at <= timezone.now():
        return Response({'error': 'Code expired. Request a new one.'}, status=400)
    if ev.attempts >= MAX_VERIFY_ATTEMPTS:
        return Response({'error': 'Too many wrong attempts. Request a new code.'}, status=429)

    if not hmac.compare_digest(ev.code_hash, _hash_code(code)):
        ev.attempts += 1
        ev.save(update_fields=['attempts'])
        remaining = max(0, MAX_VERIFY_ATTEMPTS - ev.attempts)
        return Response({'error': f'Wrong code. {remaining} attempt(s) left.'}, status=400)

    user.is_active = True
    user.save(update_fields=['is_active'])
    ev.delete()
    django_login(request, user)
    stamp_session(request)
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
        # Don't leak whether the email exists.
        return Response({'message': 'If your account is awaiting verification, a new code has been sent.',
                         'resend_available_in': RESEND_COOLDOWN_SECONDS})

    ev = EmailVerification.objects.filter(user=user).first()
    now = timezone.now()
    if ev is not None:
        elapsed = (now - ev.sent_at).total_seconds()
        if elapsed < RESEND_COOLDOWN_SECONDS:
            wait = int(RESEND_COOLDOWN_SECONDS - elapsed) + 1
            return Response({'error': f'Please wait {wait}s before requesting a new code.',
                             'resend_available_in': wait}, status=429)

    try:
        _issue_new_code(user)
    except Exception:
        log.exception('Failed to resend verification email to %s', email)
        return Response({'error': 'Failed to send email. Try again later.'}, status=502)

    return Response({'message': 'A new code was sent. Check your inbox.',
                     'resend_available_in': RESEND_COOLDOWN_SECONDS})


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
        _issue_password_reset(user)
    except Exception:
        log.exception('Failed to send password reset email to %s', email)
        return Response({'error': 'Failed to send email. Try again later.'}, status=502)
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
        return Response({'error': 'Invalid email or code.'}, status=400)

    pr = PasswordReset.objects.filter(user=user).first()
    if pr is None:
        return Response({'error': 'Invalid email or code.'}, status=400)
    if pr.expires_at <= timezone.now():
        pr.delete()
        return Response({'error': 'Code expired. Request a new one.'}, status=400)
    if pr.attempts >= MAX_VERIFY_ATTEMPTS:
        return Response({'error': 'Too many wrong attempts. Request a new code.'}, status=429)

    if not hmac.compare_digest(pr.code_hash, _hash_code(code)):
        pr.attempts += 1
        pr.save(update_fields=['attempts'])
        remaining = max(0, MAX_VERIFY_ATTEMPTS - pr.attempts)
        return Response({'error': f'Wrong code. {remaining} attempt(s) left.'}, status=400)

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
    log.info('Password changed for user_id=%s; revoked %d other session(s)', request.user.pk, revoked)
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
    username = user.username
    django_logout(request)
    user.delete()
    log.info('Account deleted: %s (user_id no longer exists)', username)
    return Response({'deleted': True})


@api_view(['GET'])
def list_models(request):
    down = unavailable_model_ids()
    models = [m for m in NVIDIA_MODELS if m['id'] not in down]
    default = DEFAULT_MODEL_ID
    if default in down and models:
        default = models[0]['id']
    return Response({'models': models, 'default': default,
                     'availability_checked_at': get_status().get('checked_at')})


@api_view(['GET'])
@permission_classes([AllowAny])
def health(request):
    return Response({'status': 'ok'})


@api_view(['GET', 'POST'])
@ratelimit(key='user', method='POST', rate='20/m', block=False)
def conversations(request):
    if request.method == 'GET':
        qs = Conversation.objects.filter(user=request.user)
        q = (request.query_params.get('q') or '').strip()
        if q:
            qs = qs.filter(Q(title__icontains=q) | Q(messages__content__icontains=q)).distinct()
        return Response(ConversationListSerializer(qs, many=True).data)

    if (r := _rate_limited(request)): return r
    title = (request.data.get('title') or 'New Chat').strip()[:200] or 'New Chat'
    model_id = request.data.get('model_id') or DEFAULT_MODEL_ID
    if model_id not in MODEL_IDS:
        return Response({'error': f'Unknown model_id: {model_id}'}, status=status.HTTP_400_BAD_REQUEST)
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
    if title is not None:
        convo.title = title.strip()[:200] or convo.title
    if model_id is not None:
        if model_id not in MODEL_IDS:
            return Response({'error': f'Unknown model_id: {model_id}'}, status=status.HTTP_400_BAD_REQUEST)
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
    })


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

    used = Attachment.objects.filter(user=request.user).aggregate(total=Sum('size'))['total'] or 0
    if used + f.size > settings.MAX_USER_STORAGE:
        return Response({'error': 'Storage quota exceeded.'}, status=413)
    extracted = extract_text(f, mime) if kind == 'document' else ''

    safe_name = re.sub(r'[^A-Za-z0-9._-]+', '_', os.path.basename(f.name or 'file'))[:120] or 'file'
    # The storage path has a 100-character limit; keep user-facing names separate.
    f.name = secrets.token_hex(12) + Path(safe_name).suffix.lower()

    # Race-free quota: lock the user row, recompute usage inside the lock, then
    # commit the new attachment. Two parallel uploads serialise here.
    User = get_user_model()
    try:
        with transaction.atomic():
            User.objects.select_for_update().filter(pk=request.user.pk).first()
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
            )
    except Exception:
        log.exception('Upload failed for user=%s name=%s', request.user.pk, safe_name)
        return Response({'error': 'Upload failed.'}, status=500)
    return Response(AttachmentSerializer(att).data, status=201)


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
                yield ('error', f'NVIDIA API error ({resp.status_code}). Try again later.')
                return
            for line in resp.iter_lines(decode_unicode=True):
                if not line:
                    continue
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


def _message_history_cost(message):
    attachments = list(message.attachments.all())
    text_chars = len(message.content or '') + sum(
        len(a.extracted_text or '') for a in attachments if a.kind == Attachment.KIND_DOCUMENT
    )
    image_bytes = sum(
        a.size for a in attachments if a.kind in (Attachment.KIND_IMAGE, Attachment.KIND_GENERATED)
    )
    return attachments, text_chars, image_bytes


def _bounded_history(messages):
    keep = []
    text_used = image_bytes_used = 0
    for message in reversed(messages[-settings.CHAT_HISTORY_MAX_MESSAGES:]):
        attachments, text_cost, image_cost = _message_history_cost(message)
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
    if override_model:
        if override_model not in MODEL_IDS:
            return Response({'error': f'Unknown model_id: {override_model}'}, status=status.HTTP_400_BAD_REQUEST)
        if override_model != convo.model_id:
            convo.model_id = override_model
            convo.save(update_fields=['model_id'])

    has_images = any(a.kind in (Attachment.KIND_IMAGE, Attachment.KIND_GENERATED) for a in attachments)
    if has_images and convo.model_id not in VISION_MODEL_IDS:
        return Response(
            {'error': 'This model does not accept images. Pick a vision model (e.g. Llama 3.2 Vision, Llama 4 Scout, Nemotron Nano VL).'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user_msg = Message.objects.create(conversation=convo, role='user', content=user_text)
    for a in attachments:
        a.message = user_msg
        a.save(update_fields=['message'])

    all_msgs = list(convo.messages.order_by('created_at').prefetch_related('attachments'))
    history = _bounded_history(all_msgs)
    if convo.system_prompt:
        history.insert(0, {'role': 'system', 'content': convo.system_prompt})

    user_msg_id = user_msg.id
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
    history = _bounded_history(all_msgs)
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
        # Delete target and everything after it.
        Message.objects.filter(conversation=convo, id__gte=target.id).delete()
        anchor = prev_user
    else:  # user
        # Delete everything strictly after the user message.
        Message.objects.filter(conversation=convo, id__gt=target.id).delete()
        anchor = target

    history = _build_history_for(convo, upto_msg_id=anchor.id)
    if not history:
        return Response({'error': 'Nothing to send.'}, status=400)

    convo_id = convo.id
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
        body = resp.text[:1000]
        log.warning('NVIDIA genai HTTP %s — %s', resp.status_code, body[:500])
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
        log.warning('NVIDIA genai returned no image: %s', str(data)[:500])
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
