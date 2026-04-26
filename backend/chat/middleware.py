"""Resolve real client IP from nginx-injected X-Real-IP / X-Forwarded-For.

Gunicorn binds to 127.0.0.1, so REMOTE_ADDR is always the loopback. We trust
X-Real-IP only when REMOTE_ADDR is loopback (i.e. the request really came
through nginx). For external requests this header would be attacker-controlled
and we ignore it.
"""

_LOOPBACK = {'127.0.0.1', '::1'}


class RealClientIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        remote = request.META.get('REMOTE_ADDR', '')
        if remote in _LOOPBACK:
            real = request.META.get('HTTP_X_REAL_IP') or request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
            if real:
                request.META['REMOTE_ADDR'] = real
        return self.get_response(request)
