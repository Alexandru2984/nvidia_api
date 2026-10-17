"""Regression coverage for anonymous CSRF, input types and session disclosure."""
import json
from datetime import timedelta
from io import BytesIO

import pytest
from django.core.cache import cache
from django.utils import timezone
from django.test import RequestFactory
from rest_framework.test import APIClient
from rest_framework.exceptions import ParseError

from chat.converters import PositiveBigIntConverter, SessionHandleConverter
from chat.models import PasswordReset
from chat.security import ObjectJSONParser
from chat.views import _hash_code
from chat.middleware import RealClientIPMiddleware

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize('endpoint', ['login', 'register', 'verify', 'resend', 'forgot', 'reset'])
def test_anonymous_auth_requires_csrf(endpoint):
    client = APIClient(enforce_csrf_checks=True)
    response = client.post(f'/api/auth/{endpoint}/', {}, format='json')
    assert response.status_code == 403


def test_login_with_valid_csrf_and_cookie_works(user):
    client = APIClient(enforce_csrf_checks=True)
    client.get('/api/auth/me/')
    response = client.post('/api/auth/login/', {
        'username': user.username, 'password': 'Hunter2pass',
    }, format='json', HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value)
    assert response.status_code == 200


def test_cross_origin_login_rejected_even_with_csrf(user):
    client = APIClient(enforce_csrf_checks=True)
    client.get('/api/auth/me/')
    response = client.post('/api/auth/login/', {
        'username': user.username, 'password': 'Hunter2pass',
    }, format='json', HTTP_X_CSRFTOKEN=client.cookies['csrftoken'].value,
        HTTP_ORIGIN='https://attacker.invalid')
    assert response.status_code == 403


@pytest.mark.parametrize('data', [[], ['username'], 'bad', 12, {'username': 42}, {'password': ['x']}])
def test_invalid_auth_json_returns_400(client, data):
    assert client.post('/api/auth/login/', data, format='json').status_code == 400


@pytest.mark.parametrize('data', [
    {'invite_code': []},
    {'max_tokens': '128'},
    {'width': 1024.0},
    {'steps': True},
    {'temperature': True},
    {'temperature': float('inf')},
    {'archived': 1},
    {'attachment_ids': [True]},
    {'attachment_ids': [0]},
    {'attachment_ids': [1 << 63]},
])
def test_structured_json_fields_reject_ambiguous_types(data):
    stream = BytesIO(json.dumps(data).encode())

    with pytest.raises(ParseError):
        ObjectJSONParser().parse(stream)


def test_structured_json_fields_accept_exact_types():
    data = {
        'invite_code': 'ABCD-EFGH-JKLM-NPQR-STUV',
        'max_tokens': 128,
        'temperature': 0.5,
        'archived': False,
        'attachment_ids': [1, (1 << 63) - 1],
    }

    assert ObjectJSONParser().parse(BytesIO(json.dumps(data).encode())) == data


@pytest.mark.parametrize('path', [
    '/api/conversations/9223372036854775808/',
    '/api/conversations/9999999999999999999/export/',
    '/api/conversations/9999999999999999999/messages/',
    '/api/messages/9999999999999999999/',
    '/api/messages/9999999999999999999/regenerate/',
    '/api/attachments/9999999999999999999/',
    '/api/attachments/9999999999999999999/preview/',
    '/api/attachments/9999999999999999999/download/',
])
def test_oversized_persistence_ids_are_rejected_by_the_router(auth_client, path):
    assert auth_client.get(path).status_code == 404


def test_identifier_converters_enforce_exact_domains():
    bigint = PositiveBigIntConverter()
    assert bigint.to_python('9223372036854775807') == (1 << 63) - 1
    for value in ('0', '9223372036854775808'):
        with pytest.raises(ValueError):
            bigint.to_python(value)

    handle = SessionHandleConverter()
    valid = 'a' * 64
    assert handle.to_python(valid) == valid
    assert handle.to_url(valid) == valid
    for value in ('a' * 63, 'g' * 64):
        with pytest.raises(ValueError):
            handle.to_url(value)


def test_malformed_session_handle_does_not_scan_sessions(auth_client):
    assert auth_client.delete('/api/auth/sessions/not-a-handle/').status_code == 404


def test_registration_uses_password_validators(client):
    response = client.post('/api/auth/register/', {
        'username': 'newuser', 'email': 'new@example.com', 'password': '123456789',
    }, format='json')
    assert response.status_code == 400


def test_verification_does_not_claim_login_for_active_account(client, user):
    response = client.post('/api/auth/verify/', {'email': user.email, 'code': '123456'}, format='json')
    assert response.status_code == 400
    assert 'username' not in response.json()


def test_reset_code_cannot_be_replayed(client, user):
    PasswordReset.objects.create(user=user, code_hash=_hash_code('123456'),
        sent_at=timezone.now(), expires_at=timezone.now() + timedelta(minutes=10))
    data = {'email': user.email, 'code': '123456', 'password': 'NewHunter2pass'}
    assert client.post('/api/auth/reset/', data, format='json').status_code == 200
    assert client.post('/api/auth/reset/', data, format='json').status_code == 400


def test_session_handles_cannot_authenticate(auth_client):
    response = auth_client.get('/api/auth/sessions/')
    handle = response.json()[0]['id']
    assert handle != auth_client.session.session_key
    attacker = APIClient()
    attacker.cookies['sessionid'] = handle
    assert attacker.get('/api/auth/me/').json()['username'] is None
    assert 'no-store' in response['Cache-Control']


@pytest.mark.parametrize('remote,real,forwarded,expected', [
    ('127.0.0.1', '198.51.100.3', '', '198.51.100.3'),
    ('', '2001:db8::3', '', '2001:db8::3'),
    ('127.0.0.1', 'garbage', '', '127.0.0.1'),
    ('127.0.0.1', '', '198.51.100.3', '127.0.0.1'),
    ('203.0.113.1', '198.51.100.3', '', '203.0.113.1'),
])
def test_ip_resolution_trusts_only_nginx_header(remote, real, forwarded, expected):
    request = RequestFactory().get('/', REMOTE_ADDR=remote, HTTP_X_REAL_IP=real,
        HTTP_X_FORWARDED_FOR=forwarded)
    assert RealClientIPMiddleware(lambda r: r.META['REMOTE_ADDR'])(request) == expected


@pytest.mark.parametrize('real', ['', 'garbage'])
def test_unix_socket_request_requires_valid_nginx_client_ip(real, caplog):
    request = RequestFactory().get(
        '/api/auth/login/',
        REMOTE_ADDR='',
        HTTP_X_REAL_IP=real,
        HTTP_X_FORWARDED_FOR='198.51.100.9',
    )

    response = RealClientIPMiddleware(lambda _: None)(request)

    assert response.status_code == 400
    assert 'event=proxy_client_ip_invalid' in caplog.text


def test_login_rate_limit_accepts_unix_socket_nginx_ip(client, user, settings):
    settings.RATELIMIT_ENABLE = True
    cache.clear()

    response = client.post(
        '/api/auth/login/',
        {'username': user.username, 'password': 'Hunter2pass'},
        format='json',
        REMOTE_ADDR='',
        HTTP_X_REAL_IP='198.51.100.10',
    )

    assert response.status_code == 200
