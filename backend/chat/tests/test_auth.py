"""Tests for /api/auth/* endpoints."""
import re
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.test.utils import override_settings
from django.utils import timezone

from chat.models import EmailVerification, PasswordReset


def _last_code(outbox):
    """Extract the 6-digit code from the most recent email body."""
    body = outbox[-1].body
    m = re.search(r'\b(\d{6})\b', body)
    assert m is not None, f'no 6-digit code in email body: {body!r}'
    return m.group(1)


@pytest.mark.django_db
class TestRegister:
    def test_creates_inactive_user_and_sends_email(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 201
        User = get_user_model()
        u = User.objects.get(username='newuser')
        assert u.is_active is False
        assert len(mail.outbox) == 1
        assert 'new@example.com' in mail.outbox[0].to

    def test_username_validation(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'a', 'email': 'a@b.com', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 400

    def test_email_validation(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'not-an-email', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 400

    def test_password_too_short(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'a@b.com', 'password': '1234',
        }, format='json')
        assert r.status_code == 400

    def test_password_too_long(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'a@b.com', 'password': 'x' * 200,
        }, format='json')
        assert r.status_code == 400

    def test_duplicate_username(self, client, user):
        r = client.post('/api/auth/register/', {
            'username': user.username, 'email': 'other@example.com', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 409

    def test_duplicate_email_case_insensitive(self, client, user):
        r = client.post('/api/auth/register/', {
            'username': 'different', 'email': user.email.upper(), 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 409

    def test_honeypot_returns_fake_201_no_user_no_email(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'bot', 'email': 'bot@x.com', 'password': 'Hunter2pass',
            'website': 'http://spam.test',
        }, format='json')
        assert r.status_code == 201
        User = get_user_model()
        assert not User.objects.filter(username='bot').exists()
        assert mail.outbox == []


@pytest.mark.django_db
class TestVerify:
    def test_correct_code_activates_user(self, client):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        code = _last_code(mail.outbox)
        r = client.post('/api/auth/verify/', {'email': 'new@example.com', 'code': code}, format='json')
        assert r.status_code == 200
        assert r.json()['verified'] is True
        User = get_user_model()
        assert User.objects.get(username='newuser').is_active is True

    def test_wrong_code_increments_attempts(self, client):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        r = client.post('/api/auth/verify/', {'email': 'new@example.com', 'code': '000000'}, format='json')
        assert r.status_code == 400
        ev = EmailVerification.objects.get()
        assert ev.attempts == 1

    def test_expired_code(self, client):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        ev = EmailVerification.objects.get()
        ev.expires_at = timezone.now() - timedelta(seconds=1)
        ev.save()
        r = client.post('/api/auth/verify/', {'email': 'new@example.com', 'code': '123456'}, format='json')
        assert r.status_code == 400

    def test_unknown_email_returns_generic_error(self, client):
        # Should not leak whether the email exists.
        r = client.post('/api/auth/verify/', {'email': 'nope@example.com', 'code': '123456'}, format='json')
        assert r.status_code == 400
        assert r.json()['error'] == 'Invalid email or code.'

    def test_code_format_must_be_6_digits(self, client):
        r = client.post('/api/auth/verify/', {'email': 'a@b.com', 'code': 'abcdef'}, format='json')
        assert r.status_code == 400


@pytest.mark.django_db
class TestLogin:
    def test_login_success(self, client, user):
        r = client.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        assert r.status_code == 200
        assert r.json()['username'] == user.username

    def test_login_wrong_password(self, client, user):
        r = client.post('/api/auth/login/', {'username': user.username, 'password': 'wrong'}, format='json')
        assert r.status_code == 401

    def test_login_unknown_username(self, client):
        r = client.post('/api/auth/login/', {'username': 'nope', 'password': 'whatever'}, format='json')
        assert r.status_code == 401

    def test_login_long_password_rejected_without_hashing(self, client, user):
        # MAX_PASSWORD_LENGTH guard prevents DoS via expensive hashing of huge inputs.
        r = client.post('/api/auth/login/', {'username': user.username, 'password': 'x' * 200}, format='json')
        assert r.status_code == 401

    def test_login_no_response_leak_for_inactive(self, client):
        User = get_user_model()
        User.objects.create_user(username='inactive', email='i@x.com', password='Hunter2pass', is_active=False)
        r = client.post('/api/auth/login/', {'username': 'inactive', 'password': 'Hunter2pass'}, format='json')
        # Django's authenticate() rejects inactive users; we return 401, not 403.
        assert r.status_code == 401

    def test_logout(self, auth_client):
        r = auth_client.post('/api/auth/logout/')
        assert r.status_code == 200
        # auth_me after logout should show null
        r2 = auth_client.get('/api/auth/me/')
        assert r2.json()['username'] is None


@pytest.mark.django_db
class TestPasswordReset:
    def _seed_reset(self, client, user):
        r = client.post('/api/auth/forgot/', {'email': user.email}, format='json')
        assert r.status_code == 200
        return _last_code(mail.outbox)

    def test_forgot_sends_email_for_existing_user(self, client, user):
        self._seed_reset(client, user)
        assert PasswordReset.objects.filter(user=user).exists()

    def test_forgot_unknown_email_returns_generic(self, client):
        r = client.post('/api/auth/forgot/', {'email': 'nope@example.com'}, format='json')
        assert r.status_code == 200
        assert mail.outbox == []
        assert 'If an account exists' in r.json()['message']

    def test_reset_with_correct_code(self, client, user):
        code = self._seed_reset(client, user)
        r = client.post('/api/auth/reset/', {
            'email': user.email, 'code': code, 'password': 'NewHunter2pass',
        }, format='json')
        assert r.status_code == 200
        user.refresh_from_db()
        assert user.check_password('NewHunter2pass')
        assert not PasswordReset.objects.filter(user=user).exists()

    def test_reset_with_wrong_code(self, client, user):
        self._seed_reset(client, user)
        r = client.post('/api/auth/reset/', {
            'email': user.email, 'code': '000000', 'password': 'NewHunter2pass',
        }, format='json')
        assert r.status_code == 400

    def test_reset_for_unknown_email_no_leak(self, client):
        r = client.post('/api/auth/reset/', {
            'email': 'nope@example.com', 'code': '123456', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 400
        assert r.json()['error'] == 'Invalid email or code.'

    def test_reset_expired_code(self, client, user):
        self._seed_reset(client, user)
        pr = PasswordReset.objects.get(user=user)
        pr.expires_at = timezone.now() - timedelta(seconds=1)
        pr.save()
        r = client.post('/api/auth/reset/', {
            'email': user.email, 'code': '123456', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 400
        assert not PasswordReset.objects.filter(user=user).exists()


@pytest.mark.django_db
class TestRateLimit:
    def test_login_rate_limit_returns_429(self, client, user, settings):
        settings.RATELIMIT_ENABLE = True
        # 10/m on auth_login. The 11th from the same IP should fall through to 429.
        statuses = []
        for _ in range(12):
            r = client.post('/api/auth/login/', {'username': user.username, 'password': 'wrong'}, format='json')
            statuses.append(r.status_code)
        assert 429 in statuses


@pytest.mark.django_db
class TestAuthMe:
    def test_unauthenticated(self, client):
        r = client.get('/api/auth/me/')
        assert r.status_code == 200
        assert r.json()['username'] is None

    def test_authenticated_no_is_staff_leak(self, auth_client, user):
        r = auth_client.get('/api/auth/me/')
        assert r.status_code == 200
        body = r.json()
        assert body['username'] == user.username
        # Defense in depth: never expose is_staff/is_superuser to any caller.
        assert 'is_staff' not in body
        assert 'is_superuser' not in body
