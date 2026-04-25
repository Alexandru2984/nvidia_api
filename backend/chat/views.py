import hashlib
import hmac
import logging
import re
import secrets
from datetime import timedelta

import requests
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, login as django_login, logout as django_logout
from django.core.mail import EmailMultiAlternatives
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import Conversation, EmailVerification, Message
from .models_catalog import DEFAULT_MODEL_ID, MODEL_IDS, NVIDIA_MODELS
from .serializers import (
    ConversationDetailSerializer,
    ConversationListSerializer,
    MessageSerializer,
)

log = logging.getLogger(__name__)


@api_view(['GET'])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def auth_me(request):
    if request.user.is_authenticated:
        return Response({'username': request.user.username, 'is_staff': request.user.is_staff})
    return Response({'username': None})


@api_view(['POST'])
@permission_classes([AllowAny])
def auth_login(request):
    username = (request.data.get('username') or '').strip()
    password = request.data.get('password') or ''
    if not username or not password:
        return Response({'error': 'username and password required'}, status=status.HTTP_400_BAD_REQUEST)
    user = authenticate(request, username=username, password=password)
    if user is None:
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    django_login(request, user)
    return Response({'username': user.username, 'is_staff': user.is_staff})


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
    subject = 'Your NVIDIA Chat Hub verification code'
    text = (
        f'Hi {user.username},\n\n'
        f'Your verification code is: {code}\n\n'
        f'Enter this code on the verification page to activate your account.\n'
        f'The code expires in 30 minutes.\n\n'
        f"If you didn't create an account, you can ignore this email.\n\n"
        f'— NVIDIA Chat Hub\n'
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
            <td style="padding-left:12px;font-weight:600;font-size:16px;color:#e6edf3;">NVIDIA Chat Hub</td>
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
            If you didn't sign up for NVIDIA Chat Hub, you can ignore this email — your address won't be used.
          </p>
        </td></tr>
        <tr><td style="padding:14px 28px;border-top:1px solid #232a36;background:#0e131a;">
          <p style="margin:0;font-size:11px;color:#5f6b7d;">
            This is an automated message from <a href="{settings.FRONTEND_URL}" style="color:#76b900;text-decoration:none;">NVIDIA Chat Hub</a>.
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
def auth_register(request):
    username = (request.data.get('username') or '').strip()
    email = (request.data.get('email') or '').strip().lower()
    password = request.data.get('password') or ''

    if not USERNAME_RE.match(username):
        return Response({'error': 'Username must be 3-30 chars, letters/digits/underscore only.'}, status=400)
    try:
        validate_email(email)
    except ValidationError:
        return Response({'error': 'Invalid email address.'}, status=400)
    if len(password) < 8:
        return Response({'error': 'Password must be at least 8 characters.'}, status=400)

    User = get_user_model()
    if User.objects.filter(username__iexact=username).exists():
        return Response({'error': 'Username already taken.'}, status=409)
    if User.objects.filter(email__iexact=email).exists():
        return Response({'error': 'An account with this email already exists.'}, status=409)

    user = User(username=username, email=email, is_active=False)
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
def auth_verify(request):
    email = (request.data.get('email') or '').strip().lower()
    code = (request.data.get('code') or '').strip()
    if not email or not code:
        return Response({'error': 'Email and code required.'}, status=400)
    if not re.fullmatch(r'\d{6}', code):
        return Response({'error': 'Code must be 6 digits.'}, status=400)

    User = get_user_model()
    user = User.objects.filter(email__iexact=email).first()
    if user is None:
        return Response({'error': 'No account with that email.'}, status=404)
    if user.is_active:
        return Response({'verified': True, 'username': user.username})

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
    return Response({'verified': True, 'username': user.username, 'is_staff': user.is_staff})


@api_view(['POST'])
@permission_classes([AllowAny])
def auth_resend(request):
    email = (request.data.get('email') or '').strip().lower()
    if not email:
        return Response({'error': 'Email required.'}, status=400)
    User = get_user_model()
    user = User.objects.filter(email__iexact=email, is_active=False).first()
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


@api_view(['GET'])
def list_models(request):
    return Response({'models': NVIDIA_MODELS, 'default': DEFAULT_MODEL_ID})


@api_view(['GET'])
def health(request):
    return Response({'status': 'ok'})


@api_view(['GET', 'POST'])
def conversations(request):
    if request.method == 'GET':
        qs = Conversation.objects.filter(user=request.user)
        return Response(ConversationListSerializer(qs, many=True).data)

    title = (request.data.get('title') or 'New Chat').strip()[:200] or 'New Chat'
    model_id = request.data.get('model_id') or DEFAULT_MODEL_ID
    if model_id not in MODEL_IDS:
        return Response({'error': f'Unknown model_id: {model_id}'}, status=status.HTTP_400_BAD_REQUEST)
    convo = Conversation.objects.create(user=request.user, title=title, model_id=model_id)
    return Response(ConversationDetailSerializer(convo).data, status=status.HTTP_201_CREATED)


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
    convo.save()
    return Response(ConversationDetailSerializer(convo).data)


def _call_nvidia(model_id, messages, max_tokens=1024, temperature=0.7):
    payload = {
        'model': model_id,
        'messages': messages,
        'max_tokens': max_tokens,
        'temperature': temperature,
        'stream': False,
    }
    headers = {
        'Authorization': f'Bearer {settings.NVIDIA_API_KEY}',
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    resp = requests.post(settings.NVIDIA_API_URL, json=payload, headers=headers, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    choice = data['choices'][0]
    text = choice['message']['content']
    usage = data.get('usage') or {}
    return text, usage


@api_view(['POST'])
def send_message(request, pk):
    convo = get_object_or_404(Conversation, pk=pk, user=request.user)
    user_text = (request.data.get('content') or '').strip()
    if not user_text:
        return Response({'error': 'content is required'}, status=status.HTTP_400_BAD_REQUEST)

    override_model = request.data.get('model_id')
    if override_model:
        if override_model not in MODEL_IDS:
            return Response({'error': f'Unknown model_id: {override_model}'}, status=status.HTTP_400_BAD_REQUEST)
        if override_model != convo.model_id:
            convo.model_id = override_model

    user_msg = Message.objects.create(conversation=convo, role='user', content=user_text)

    history = list(convo.messages.order_by('created_at').values('role', 'content'))

    try:
        reply_text, usage = _call_nvidia(convo.model_id, history)
    except requests.HTTPError as e:
        body = e.response.text if e.response is not None else ''
        log.warning('NVIDIA API HTTP error: %s — %s', e, body[:500])
        user_msg.delete()
        return Response(
            {'error': f'NVIDIA API error ({e.response.status_code if e.response is not None else "?"})', 'detail': body[:1000]},
            status=status.HTTP_502_BAD_GATEWAY,
        )
    except requests.RequestException as e:
        log.exception('NVIDIA API request failed')
        user_msg.delete()
        return Response({'error': 'NVIDIA API request failed', 'detail': str(e)}, status=status.HTTP_502_BAD_GATEWAY)

    assistant_msg = Message.objects.create(conversation=convo, role='assistant', content=reply_text)

    if convo.title == 'New Chat':
        convo.title = user_text[:60] + ('…' if len(user_text) > 60 else '')
    convo.save()

    return Response({
        'user_message': MessageSerializer(user_msg).data,
        'assistant_message': MessageSerializer(assistant_msg).data,
        'conversation': ConversationListSerializer(convo).data,
        'usage': usage,
    })
