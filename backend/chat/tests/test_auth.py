"""Tests for /api/auth/* endpoints."""
import re
from datetime import timedelta
from io import StringIO
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.utils import timezone

from chat.models import EmailVerification, PasswordReset, RegistrationInvite
from chat.registration import generate_invite_code, hash_invite_code


def _last_code(outbox):
    """Extract the 6-digit code from the most recent email body."""
    body = outbox[-1].body
    m = re.search(r'\b(\d{6})\b', body)
    assert m is not None, f'no 6-digit code in email body: {body!r}'
    return m.group(1)


def _registration_invite(hours=1):
    code = generate_invite_code()
    invite = RegistrationInvite.objects.create(
        code_hash=hash_invite_code(code),
        expires_at=timezone.now() + timedelta(hours=hours),
    )
    return invite, code


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
        before = get_user_model().objects.count()
        r = client.post('/api/auth/register/', {
            'username': user.username, 'email': 'other@example.com', 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 201
        assert r.json() == {
            'message': 'If the account details are available, check your email for the 6-digit code.',
            'email': 'other@example.com',
            'resend_available_in': 60,
        }
        assert get_user_model().objects.count() == before
        assert mail.outbox == []

    def test_duplicate_email_case_insensitive(self, client, user):
        before = get_user_model().objects.count()
        r = client.post('/api/auth/register/', {
            'username': 'different', 'email': user.email.upper(), 'password': 'Hunter2pass',
        }, format='json')
        assert r.status_code == 201
        assert r.json()['email'] == user.email.lower()
        assert get_user_model().objects.count() == before
        assert mail.outbox == []

    def test_honeypot_returns_fake_201_no_user_no_email(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'bot', 'email': 'bot@x.com', 'password': 'Hunter2pass',
            'website': 'http://spam.test',
        }, format='json')
        assert r.status_code == 201
        User = get_user_model()
        assert not User.objects.filter(username='bot').exists()
        assert mail.outbox == []

    def test_mail_failure_matches_duplicate_response_and_removes_partial_user(self, client):
        payload = {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }
        with patch('chat.views._send_verification_email', side_effect=RuntimeError('mail unavailable')):
            failed = client.post('/api/auth/register/', payload, format='json')
        User = get_user_model()
        assert not User.objects.filter(username='newuser').exists()

        User.objects.create_user(**payload)
        duplicate = client.post('/api/auth/register/', payload, format='json')
        assert (failed.status_code, failed.json()) == (duplicate.status_code, duplicate.json())
        assert mail.outbox == []

    def test_database_rejects_case_insensitive_username_collision(self, user):
        User = get_user_model()
        with pytest.raises(IntegrityError), transaction.atomic():
            User.objects.create_user(
                username=user.username.swapcase(), email='unique@example.com', password='Hunter2pass',
            )

    def test_database_rejects_case_insensitive_email_collision(self, user):
        User = get_user_model()
        with pytest.raises(IntegrityError), transaction.atomic():
            User.objects.create_user(
                username='unique_name', email=user.email.swapcase(), password='Hunter2pass',
            )

    def test_auth_me_advertises_registration_mode(self, client, settings):
        settings.REGISTRATION_MODE = 'invite'
        assert client.get('/api/auth/me/').json() == {
            'username': None, 'registration_mode': 'invite',
        }

    def test_closed_registration_writes_nothing(self, client, settings):
        settings.REGISTRATION_MODE = 'closed'
        response = client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        assert response.status_code == 403
        assert response.json()['code'] == 'registration_closed'
        assert not get_user_model().objects.exists()

    def test_invite_mode_requires_a_valid_code(self, client, settings):
        settings.REGISTRATION_MODE = 'invite'
        with patch('django.contrib.auth.base_user.AbstractBaseUser.set_password') as set_password:
            response = client.post('/api/auth/register/', {
                'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
                'invite_code': 'invalid',
            }, format='json')
        assert response.status_code == 403
        assert response.json()['code'] == 'invalid_invitation'
        set_password.assert_not_called()
        assert not get_user_model().objects.exists()

    def test_invite_is_consumed_once_after_email_succeeds(self, client, settings):
        settings.REGISTRATION_MODE = 'invite'
        invite, code = _registration_invite()
        response = client.post('/api/auth/register/', {
            'username': 'invited', 'email': 'invited@example.com', 'password': 'Hunter2pass',
            'invite_code': code.lower(),
        }, format='json')
        assert response.status_code == 201
        invite.refresh_from_db()
        assert invite.used_at is not None
        assert invite.used_by.username == 'invited'
        assert len(mail.outbox) == 1

        replay = client.post('/api/auth/register/', {
            'username': 'replay', 'email': 'replay@example.com', 'password': 'Hunter2pass',
            'invite_code': code,
        }, format='json')
        assert replay.status_code == 403
        assert not get_user_model().objects.filter(username='replay').exists()

    def test_expired_invite_is_rejected(self, client, settings):
        settings.REGISTRATION_MODE = 'invite'
        invite, code = _registration_invite()
        RegistrationInvite.objects.filter(pk=invite.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1),
        )
        response = client.post('/api/auth/register/', {
            'username': 'late', 'email': 'late@example.com', 'password': 'Hunter2pass',
            'invite_code': code,
        }, format='json')
        assert response.status_code == 403

    def test_duplicate_identifier_does_not_consume_invite(self, client, user, settings):
        settings.REGISTRATION_MODE = 'invite'
        invite, code = _registration_invite()
        response = client.post('/api/auth/register/', {
            'username': user.username, 'email': 'other@example.com', 'password': 'Hunter2pass',
            'invite_code': code,
        }, format='json')
        assert response.status_code == 201
        invite.refresh_from_db()
        assert invite.used_at is None
        assert invite.used_by is None

    def test_mail_failure_rolls_back_user_and_invite(self, client, settings):
        settings.REGISTRATION_MODE = 'invite'
        invite, code = _registration_invite()
        with patch('chat.views._send_verification_email', side_effect=RuntimeError('mail unavailable')):
            response = client.post('/api/auth/register/', {
                'username': 'retryable', 'email': 'retry@example.com', 'password': 'Hunter2pass',
                'invite_code': code,
            }, format='json')
        assert response.status_code == 201
        assert not get_user_model().objects.filter(username='retryable').exists()
        invite.refresh_from_db()
        assert invite.used_at is None
        assert invite.used_by is None

    def test_honeypot_does_not_require_or_consume_invite(self, client, settings):
        settings.REGISTRATION_MODE = 'invite'
        invite, _ = _registration_invite()
        response = client.post('/api/auth/register/', {
            'username': 'botuser', 'email': 'bot@example.com', 'password': 'Hunter2pass',
            'website': 'https://spam.invalid',
        }, format='json')
        assert response.status_code == 201
        invite.refresh_from_db()
        assert invite.used_at is None
        assert not get_user_model().objects.filter(username='botuser').exists()

    def test_management_command_prints_code_once_and_stores_only_hash(self):
        output = StringIO()
        call_command('create_registration_invite', '--expires-hours=24', stdout=output)
        code = re.search(
            r'Invitation code \(shown once\): ([A-Z2-9-]+)', output.getvalue(),
        ).group(1)
        invite = RegistrationInvite.objects.get()
        assert invite.code_hash == hash_invite_code(code)
        assert code not in invite.code_hash

        with pytest.raises(CommandError):
            call_command('create_registration_invite', '--expires-hours=0', stdout=StringIO())


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

    def test_successful_verification_is_security_logged(self, client, caplog):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        code = _last_code(mail.outbox)
        caplog.set_level('WARNING', logger='security')
        response = client.post(
            '/api/auth/verify/', {'email': 'new@example.com', 'code': code}, format='json',
        )
        assert response.status_code == 200
        assert any('event=registration_verified' in record.message for record in caplog.records)

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
        assert r.json()['error'] == 'Invalid or expired email or code.'

    def test_known_and_unknown_email_have_identical_wrong_code_response(self, client):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        known = client.post(
            '/api/auth/verify/', {'email': 'new@example.com', 'code': '000000'}, format='json',
        )
        unknown = client.post(
            '/api/auth/verify/', {'email': 'nope@example.com', 'code': '000000'}, format='json',
        )
        assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())

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

    def test_forgot_mail_failure_is_generic_and_rolls_back_code(self, client, user):
        with patch('chat.views._send_password_reset_email', side_effect=RuntimeError('mail unavailable')):
            known = client.post('/api/auth/forgot/', {'email': user.email}, format='json')
        unknown = client.post('/api/auth/forgot/', {'email': 'nope@example.com'}, format='json')
        assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())
        assert not PasswordReset.objects.filter(user=user).exists()

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
        assert r.json()['error'] == 'Invalid or expired email or code.'

    def test_known_and_unknown_email_have_identical_wrong_code_response(self, client, user):
        self._seed_reset(client, user)
        known = client.post('/api/auth/reset/', {
            'email': user.email, 'code': '000000', 'password': 'NewHunter2pass',
        }, format='json')
        unknown = client.post('/api/auth/reset/', {
            'email': 'nope@example.com', 'code': '000000', 'password': 'NewHunter2pass',
        }, format='json')
        assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())

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
class TestResendVerification:
    def test_cooldown_and_unknown_email_have_identical_response(self, client):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        known = client.post('/api/auth/resend/', {'email': 'new@example.com'}, format='json')
        unknown = client.post('/api/auth/resend/', {'email': 'nope@example.com'}, format='json')
        assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())
        assert len(mail.outbox) == 1

    def test_mail_failure_is_generic_and_preserves_previous_code(self, client):
        client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'Hunter2pass',
        }, format='json')
        verification = EmailVerification.objects.get()
        verification.sent_at = timezone.now() - timedelta(minutes=2)
        verification.save(update_fields=['sent_at'])
        previous_hash = verification.code_hash
        previous_sent_at = verification.sent_at

        with patch('chat.views._send_verification_email', side_effect=RuntimeError('mail unavailable')):
            failed = client.post('/api/auth/resend/', {'email': 'new@example.com'}, format='json')
        unknown = client.post('/api/auth/resend/', {'email': 'nope@example.com'}, format='json')

        verification.refresh_from_db()
        assert (failed.status_code, failed.json()) == (unknown.status_code, unknown.json())
        assert verification.code_hash == previous_hash
        assert verification.sent_at == previous_sent_at


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
