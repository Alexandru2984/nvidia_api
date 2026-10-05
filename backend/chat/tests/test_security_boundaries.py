"""Regression coverage for anonymous CSRF, input types and session disclosure."""
from datetime import timedelta

import pytest
from django.utils import timezone
from django.test import RequestFactory
from rest_framework.test import APIClient

from chat.models import PasswordReset
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
    ('127.0.0.1', 'garbage', '', '127.0.0.1'),
    ('127.0.0.1', '', '198.51.100.3', '127.0.0.1'),
    ('203.0.113.1', '198.51.100.3', '', '203.0.113.1'),
])
def test_ip_resolution_trusts_only_nginx_header(remote, real, forwarded, expected):
    request = RequestFactory().get('/', REMOTE_ADDR=remote, HTTP_X_REAL_IP=real,
        HTTP_X_FORWARDED_FOR=forwarded)
    assert RealClientIPMiddleware(lambda r: r.META['REMOTE_ADDR'])(request) == expected
