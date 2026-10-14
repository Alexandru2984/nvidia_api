"""Indexed session inventory, revocation, and absolute-lifetime enforcement."""
import logging
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth import logout as django_logout
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.dateparse import parse_datetime
from django_ratelimit.decorators import ratelimit
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import AuthenticatedSession
from .recent_auth import require_recent_auth

log = logging.getLogger(__name__)
security_log = logging.getLogger('security')

ABSOLUTE_EXPIRY_SESSION_KEY = 'absolute_expires_at'


def _rate_limited(request):
    if not getattr(request, 'limited', False):
        return None
    security_log.warning(
        'event=rate_limit path=%s user_id=%s',
        request.path[:160],
        request.user.pk,
    )
    return Response({'error': 'Too many requests. Slow down and try again.'}, status=429)


def session_handle(session_key):
    """A revocation identifier, never a bearer credential usable as a cookie."""
    return salted_hmac('chat.session.handle', session_key, algorithm='sha256').hexdigest()


def _session_datetime(value):
    if isinstance(value, str):
        try:
            value = parse_datetime(value)
        except (TypeError, ValueError):
            return None
    if value is None or not timezone.is_aware(value):
        return None
    return value


def _session_times(request, record=None):
    now = timezone.now()
    login_at = record.login_at if record is not None else _session_datetime(
        request.session.get('login_at'),
    )
    if login_at is None or login_at > now:
        login_at = now
    configured_expiry = login_at + timedelta(
        seconds=settings.SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    )
    signed_expiry = _session_datetime(
        request.session.get(ABSOLUTE_EXPIRY_SESSION_KEY),
    )
    candidates = [configured_expiry]
    if signed_expiry is not None:
        candidates.append(signed_expiry)
    if record is not None:
        candidates.append(record.absolute_expires_at)
    return login_at, min(candidates)


def _persist_session_record(
    request,
    *,
    login_at,
    absolute_expires_at,
    enforce_limit=True,
):
    request.session['login_at'] = login_at.isoformat()
    request.session[ABSOLUTE_EXPIRY_SESSION_KEY] = absolute_expires_at.isoformat()
    request.session.save()
    session_key = request.session.session_key
    if not session_key:
        raise RuntimeError('Authenticated session has no persistence key.')

    user_agent = (request.META.get('HTTP_USER_AGENT') or '')[:300]
    ip_address = (request.META.get('REMOTE_ADDR') or '')[:45]
    with transaction.atomic():
        get_user_model().objects.select_for_update().only('pk').get(
            pk=request.user.pk,
        )
        AuthenticatedSession.objects.update_or_create(
            session_id=session_key,
            defaults={
                'user_id': request.user.pk,
                'handle': session_handle(session_key),
                'user_agent': user_agent,
                'ip_address': ip_address,
                'login_at': login_at,
                'absolute_expires_at': absolute_expires_at,
            },
        )
        overflow_keys = []
        if enforce_limit:
            overflow_keys = list(
                AuthenticatedSession.objects.filter(user_id=request.user.pk)
                .exclude(session_id=session_key)
                .order_by('-login_at', '-session_id')
                .values_list('session_id', flat=True)[
                    max(0, settings.SESSION_MAX_ACTIVE_PER_USER - 1):
                ]
            )
            if overflow_keys:
                Session.objects.filter(session_key__in=overflow_keys).delete()
    if overflow_keys:
        security_log.warning(
            'event=session_limit_enforced user_id=%s revoked=%s',
            request.user.pk,
            len(overflow_keys),
        )
    return len(overflow_keys)


def stamp_session(request):
    """Create indexed metadata and a fixed absolute deadline after login."""
    now = timezone.now()
    absolute_expires_at = now + timedelta(
        seconds=settings.SESSION_ABSOLUTE_MAX_AGE_SECONDS,
    )
    return _persist_session_record(
        request,
        login_at=now,
        absolute_expires_at=absolute_expires_at,
    )


def sync_session_record(request):
    """Re-link metadata after a deliberate session-key rotation."""
    login_at, absolute_expires_at = _session_times(request)
    return _persist_session_record(
        request,
        login_at=login_at,
        absolute_expires_at=absolute_expires_at,
    )


def enforce_absolute_session(request):
    """Log out expired/corrupt sessions and lazily index legitimate legacy ones."""
    if not request.user.is_authenticated:
        return True
    session_key = request.session.session_key
    if not session_key:
        return True
    record = AuthenticatedSession.objects.filter(session_id=session_key).first()
    if record is not None and record.user_id != request.user.pk:
        security_log.warning(
            'event=session_registry_mismatch user_id=%s',
            request.user.pk,
        )
        django_logout(request)
        return False

    login_at, absolute_expires_at = _session_times(request, record)
    if absolute_expires_at <= timezone.now():
        user_id = request.user.pk
        django_logout(request)
        security_log.warning('event=session_absolute_expired user_id=%s', user_id)
        return False

    signed_expiry = _session_datetime(
        request.session.get(ABSOLUTE_EXPIRY_SESSION_KEY),
    )
    if record is None or signed_expiry != absolute_expires_at:
        _persist_session_record(
            request,
            login_at=login_at,
            absolute_expires_at=absolute_expires_at,
        )
    return True


def _active_user_sessions(user):
    now = timezone.now()
    return (
        AuthenticatedSession.objects.filter(
            user=user,
            session__expire_date__gt=now,
            absolute_expires_at__gt=now,
        )
        .select_related('session')
        .order_by('-login_at', '-session_id')
    )


def revoke_user_sessions(user, except_key=None):
    """Delete indexed sessions for one owner without decoding the global table."""
    with transaction.atomic():
        get_user_model().objects.select_for_update().only('pk').get(pk=user.pk)
        records = AuthenticatedSession.objects.filter(user=user)
        if except_key:
            records = records.exclude(session_id=except_key)
        session_keys = list(records.values_list('session_id', flat=True))
        if session_keys:
            Session.objects.filter(session_key__in=session_keys).delete()
    return len(session_keys)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='20/m', block=False)
def list_sessions(request):
    if (response := _rate_limited(request)) is not None:
        return response
    current_key = request.session.session_key
    items = []
    for record in _active_user_sessions(request.user):
        items.append({
            'id': record.handle,
            'ip': record.ip_address,
            'ua': record.user_agent,
            'login_at': record.login_at,
            'expires_at': min(
                record.session.expire_date,
                record.absolute_expires_at,
            ),
            'absolute_expires_at': record.absolute_expires_at,
            'current': record.session_id == current_key,
        })
    return Response(items)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='20/m', block=False)
def revoke_session(request, key):
    """Revoke one owner-scoped session by its non-bearer indexed handle."""
    if (response := _rate_limited(request)) is not None:
        return response
    if (response := require_recent_auth(request)) is not None:
        return response
    if constant_time_compare(key, session_handle(request.session.session_key)):
        return Response(
            {'error': 'Use /auth/logout/ to end your current session.'},
            status=400,
        )
    record = AuthenticatedSession.objects.filter(
        user=request.user,
        handle=key,
    ).first()
    if record is None:
        return Response({'error': 'Session not found.'}, status=404)
    Session.objects.filter(session_key=record.session_id).delete()
    security_log.warning('event=session_revoked user_id=%s', request.user.pk)
    return Response(status=204)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
@ratelimit(key='user', rate='10/m', block=False)
def revoke_other_sessions(request):
    """Revoke all indexed sessions except the current one."""
    if (response := _rate_limited(request)) is not None:
        return response
    if (response := require_recent_auth(request)) is not None:
        return response
    deleted = revoke_user_sessions(
        request.user,
        except_key=request.session.session_key,
    )
    if deleted:
        security_log.warning(
            'event=other_sessions_revoked user_id=%s count=%s',
            request.user.pk,
            deleted,
        )
    return Response({'revoked': deleted})
