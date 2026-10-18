"""Short-lived, session-bound authentication for sensitive account actions."""
import hashlib
import hmac
import logging
import time

from django.conf import settings
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.db import transaction
from rest_framework.response import Response

from .passwords import upgrade_password_hash, verify_password_without_upgrade

security_log = logging.getLogger('security')

RECENT_AUTH_SESSION_KEY = 'recent_authentication'


def _credential_fingerprint(user):
    payload = f'recent-auth:{user.pk}:{user.password}'.encode('utf-8')
    return hmac.new(
        settings.SECRET_KEY.encode('utf-8'),
        payload,
        hashlib.sha256,
    ).hexdigest()


def mark_recent_auth(request):
    """Bind a recent-auth marker to this user, session, and password hash."""
    request.session[RECENT_AUTH_SESSION_KEY] = {
        'user_id': str(request.user.pk),
        'authenticated_at': int(time.time()),
        'credential': _credential_fingerprint(request.user),
    }


def clear_recent_auth(request):
    request.session.pop(RECENT_AUTH_SESSION_KEY, None)


def recent_auth_seconds_remaining(request):
    marker = request.session.get(RECENT_AUTH_SESSION_KEY)
    if not request.user.is_authenticated or not isinstance(marker, dict):
        return 0
    authenticated_at = marker.get('authenticated_at')
    credential = marker.get('credential')
    if (
        not isinstance(authenticated_at, int)
        or isinstance(authenticated_at, bool)
        or not isinstance(credential, str)
        or marker.get('user_id') != str(request.user.pk)
    ):
        clear_recent_auth(request)
        return 0
    age = int(time.time()) - authenticated_at
    if not 0 <= age <= settings.RECENT_AUTH_MAX_AGE_SECONDS:
        clear_recent_auth(request)
        return 0
    if not hmac.compare_digest(credential, _credential_fingerprint(request.user)):
        clear_recent_auth(request)
        return 0
    return settings.RECENT_AUTH_MAX_AGE_SECONDS - age


def require_recent_auth(request):
    """Return a 403 response when the session lacks fresh strong authentication."""
    if recent_auth_seconds_remaining(request) > 0:
        return None
    from .twofactor import login_requires_2fa

    return Response({
        'error': 'Confirm your identity to continue.',
        'reauthentication_required': True,
        'two_factor_required': login_requires_2fa(request.user),
    }, status=403)


def confirm_recent_auth(request, password, code=''):
    """Verify current credentials, including 2FA when enabled, and mark fresh."""
    from .twofactor import login_requires_2fa, verify_for_login

    two_factor_required = login_requires_2fa(request.user)
    if not isinstance(password, str) or len(password) > settings.MAX_PASSWORD_LENGTH:
        security_log.warning(
            'event=recent_auth_failed user_id=%s factor=password',
            request.user.pk,
        )
        return Response({
            'error': 'Authentication failed.',
            'two_factor_required': two_factor_required,
        }, status=401)
    code = code.strip() if isinstance(code, str) else ''
    with transaction.atomic():
        locked_user = get_user_model().objects.select_for_update().get(
            pk=request.user.pk,
        )
        password_valid, password_needs_upgrade = verify_password_without_upgrade(
            password,
            locked_user.password,
        )
        if not password_valid:
            security_log.warning(
                'event=recent_auth_failed user_id=%s factor=password',
                request.user.pk,
            )
            return Response({
                'error': 'Authentication failed.',
                'two_factor_required': two_factor_required,
            }, status=401)
        if two_factor_required and not code:
            return Response({
                'error': 'Two-factor code required.',
                'two_factor_required': True,
            }, status=401)
        if two_factor_required and not verify_for_login(locked_user, code):
            security_log.warning(
                'event=recent_auth_failed user_id=%s factor=two_factor',
                request.user.pk,
            )
            return Response({
                'error': 'Authentication failed.',
                'two_factor_required': True,
            }, status=401)
        if upgrade_password_hash(locked_user, password, password_needs_upgrade):
            from .sessions import revoke_user_sessions, sync_session_record

            request.user.password = locked_user.password
            update_session_auth_hash(request, request.user)
            sync_session_record(request)
            revoked = revoke_user_sessions(
                request.user,
                except_key=request.session.session_key,
            )
            security_log.info(
                'event=password_hash_upgraded user_id=%s sessions_revoked=%s',
                request.user.pk,
                revoked,
            )
        mark_recent_auth(request)
    security_log.info('event=recent_auth_succeeded user_id=%s', request.user.pk)
    return None
