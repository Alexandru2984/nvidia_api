"""Per-user session inventory + revocation. Backed by django_session.

We piggyback metadata (UA, IP, login_at) into request.session so it's stored
alongside the auth user id in the encoded session_data. No new tables needed."""
import logging

from django.contrib.sessions.models import Session
from django.utils import timezone
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

log = logging.getLogger(__name__)


def stamp_session(request):
    """Call after a successful django_login() to record UA/IP/login time on the
    new session row. Cheap enough to do on every login."""
    ua = (request.META.get('HTTP_USER_AGENT') or '')[:300]
    ip = request.META.get('REMOTE_ADDR') or ''
    request.session['ua'] = ua
    request.session['ip'] = ip
    request.session['login_at'] = timezone.now().isoformat()


def _user_sessions(user):
    """Return all *active* (non-expired) sessions for `user`, decoded."""
    out = []
    now = timezone.now()
    for s in Session.objects.filter(expire_date__gt=now):
        try:
            data = s.get_decoded()
        except Exception:
            continue
        uid = data.get('_auth_user_id')
        if uid is None or str(uid) != str(user.pk):
            continue
        out.append((s, data))
    return out


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_sessions(request):
    current_key = request.session.session_key
    items = []
    for s, data in _user_sessions(request.user):
        items.append({
            'id': s.session_key,
            'ip': data.get('ip', ''),
            'ua': data.get('ua', ''),
            'login_at': data.get('login_at'),
            'expires_at': s.expire_date,
            'current': s.session_key == current_key,
        })
    items.sort(key=lambda x: x['login_at'] or '', reverse=True)
    return Response(items)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def revoke_session(request, key):
    """Revoke one session by key. Must belong to the current user."""
    if key == request.session.session_key:
        return Response(
            {'error': 'Use /auth/logout/ to end your current session.'},
            status=400,
        )
    for s, _ in _user_sessions(request.user):
        if s.session_key == key:
            s.delete()
            return Response(status=204)
    return Response({'error': 'Session not found.'}, status=404)


@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def revoke_other_sessions(request):
    """Revoke all of the user's sessions except the current one. Useful as a
    'sign out everywhere else' panic button."""
    current_key = request.session.session_key
    deleted = 0
    for s, _ in _user_sessions(request.user):
        if s.session_key == current_key:
            continue
        s.delete()
        deleted += 1
    return Response({'revoked': deleted})
