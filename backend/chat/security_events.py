"""Privacy-minimized, machine-detectable security audit events."""
import hashlib
import hmac
import logging

from django.conf import settings
from django.contrib.auth.signals import (
    user_logged_in,
    user_logged_out,
    user_login_failed,
)
from django.dispatch import receiver

security_log = logging.getLogger('security')


def actor_for_request(request):
    """Return a stable actor label without writing a raw client IP to this log."""
    if request is not None:
        user = getattr(request, 'user', None)
        if user is not None and getattr(user, 'is_authenticated', False):
            return f'user:{user.pk}'
        ip = request.META.get('REMOTE_ADDR', '')
    else:
        ip = ''
    digest = hmac.new(
        settings.SECRET_KEY.encode(), ip.encode(), hashlib.sha256,
    ).hexdigest()[:16]
    return f'network:{digest}'


@receiver(user_login_failed)
def log_login_failed(sender, credentials, request, **kwargs):
    security_log.warning('event=auth_failed actor=%s', actor_for_request(request))


@receiver(user_logged_in)
def log_login_success(sender, request, user, **kwargs):
    if request.path.startswith('/admin/'):
        security_log.warning('event=admin_login user_id=%s', user.pk)
    else:
        security_log.info('event=auth_login user_id=%s', user.pk)


@receiver(user_logged_out)
def log_logout(sender, request, user, **kwargs):
    if user is not None:
        security_log.info('event=auth_logout user_id=%s', user.pk)
