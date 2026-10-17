"""Resolve the real client IP from nginx-injected X-Real-IP.

Gunicorn uses a permissioned Unix socket in production, where REMOTE_ADDR is
empty. Local development may still use loopback TCP. We trust X-Real-IP only
for those two origin shapes; for external TCP requests the header would be
attacker-controlled and is ignored. A Unix-socket request without a valid
nginx-set address fails closed before IP-keyed rate limiting.
"""

import logging
from ipaddress import ip_address

from django.http import HttpResponse

_LOOPBACK = {'127.0.0.1', '::1'}
security_log = logging.getLogger('security')


class RealClientIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        remote = request.META.get('REMOTE_ADDR', '')
        if not remote or remote in _LOOPBACK:
            # nginx overwrites X-Real-IP. Never fall back to client-supplied XFF.
            real = request.META.get('HTTP_X_REAL_IP', '').strip()
            if real:
                try:
                    request.META['REMOTE_ADDR'] = str(ip_address(real))
                except ValueError:
                    if not remote:
                        security_log.error('event=proxy_client_ip_invalid')
                        return HttpResponse(
                            'Invalid proxy client address.',
                            status=400,
                            content_type='text/plain; charset=utf-8',
                        )
            elif not remote:
                security_log.error('event=proxy_client_ip_invalid')
                return HttpResponse(
                    'Missing proxy client address.',
                    status=400,
                    content_type='text/plain; charset=utf-8',
                )
        return self.get_response(request)


class PrivateAPIResponseMiddleware:
    """Sensitive responses must not survive in browser or shared caches."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith('/api/'):
            response['Cache-Control'] = 'private, no-store, no-transform'
        return response


class AbsoluteSessionMiddleware:
    """Apply the fixed authenticated-session deadline after auth resolution."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from .sessions import enforce_absolute_session

        enforce_absolute_session(request)
        return self.get_response(request)


class StaffAdminTwoFactorMiddleware:
    """Deny Django admin unless this staff session completed application 2FA.

    The stock Django admin form verifies only a password. Staff must sign in via
    the main application (or enroll 2FA there) before opening `/admin/`.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not request.path.startswith('/admin/'):
            return self.get_response(request)

        from .security_events import actor_for_request
        from .twofactor import staff_2fa_verified

        if not staff_2fa_verified(request):
            security_log.warning('event=admin_access_denied actor=%s', actor_for_request(request))
            return HttpResponse(
                'Admin access requires a staff account with 2FA verified through the main application.',
                status=403,
                content_type='text/plain; charset=utf-8',
            )

        if not request.session.get('admin_access_logged'):
            security_log.warning('event=admin_access user_id=%s', request.user.pk)
            request.session['admin_access_logged'] = True
        return self.get_response(request)
