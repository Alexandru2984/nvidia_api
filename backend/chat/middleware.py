"""Resolve real client IP from nginx-injected X-Real-IP / X-Forwarded-For.

Gunicorn binds to 127.0.0.1, so REMOTE_ADDR is always the loopback. We trust
X-Real-IP only when REMOTE_ADDR is loopback (i.e. the request really came
through nginx). For external requests this header would be attacker-controlled
and we ignore it.
"""

from ipaddress import ip_address

_LOOPBACK = {'127.0.0.1', '::1'}


class RealClientIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        remote = request.META.get('REMOTE_ADDR', '')
        if remote in _LOOPBACK:
            # nginx overwrites X-Real-IP. Never fall back to client-supplied XFF.
            real = request.META.get('HTTP_X_REAL_IP', '').strip()
            if real:
                try:
                    request.META['REMOTE_ADDR'] = str(ip_address(real))
                except ValueError:
                    pass
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
