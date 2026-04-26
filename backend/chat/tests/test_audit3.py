"""Regression tests for Audit #3 findings."""
import threading
from unittest.mock import patch

import pyotp
import pytest
from django.contrib.sessions.models import Session
from django.core import mail
from rest_framework.test import APIClient

from chat.models import PasswordReset, TwoFactor
from chat.twofactor import (
    LOCKOUT_DURATION,
    LOCKOUT_THRESHOLD,
    _decrypt_secret,
    _encrypt_secret,
    _hash_recovery,
)


def _enable_2fa(client, user):
    enroll = client.post('/api/auth/2fa/enroll/').json()
    secret = enroll['secret']
    client.post('/api/auth/2fa/verify-enroll/', {'code': pyotp.TOTP(secret).now()}, format='json')
    TwoFactor.objects.filter(user=user).update(last_totp_step=0)
    return secret


@pytest.mark.django_db
class TestSecretEncryption:
    """Finding #7: TOTP secret stored Fernet-encrypted at rest."""

    def test_enroll_stores_encrypted_secret(self, auth_client, user):
        body = auth_client.post('/api/auth/2fa/enroll/').json()
        plain = body['secret']  # what the client sees / scans
        stored = TwoFactor.objects.get(user=user).secret
        # The DB row must NOT match the plaintext base32 secret.
        assert stored != plain
        # And must round-trip through the helper.
        assert _decrypt_secret(stored) == plain

    def test_legacy_plaintext_secret_still_decrypts(self):
        # Pre-migration rows held base32 plaintext; _decrypt_secret falls through.
        legacy = pyotp.random_base32()
        assert _decrypt_secret(legacy) == legacy

    def test_round_trip(self):
        for _ in range(3):
            s = pyotp.random_base32()
            assert _decrypt_secret(_encrypt_secret(s)) == s


@pytest.mark.django_db
class TestTOTPReplay:
    """Finding #3: same valid TOTP code can no longer be used twice."""

    def test_same_code_rejected_second_time(self, auth_client, client, user):
        secret = _enable_2fa(auth_client, user)
        auth_client.logout()
        code = pyotp.TOTP(secret).now()

        r1 = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': code,
        }, format='json')
        assert r1.status_code == 200
        client.logout()

        # Same code, same window → reject (replay).
        r2 = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': code,
        }, format='json')
        assert r2.status_code == 401
        assert r2.json().get('two_factor_required') is True


@pytest.mark.django_db
class TestRecoveryCodeRace:
    """Finding #2: recovery code consumption runs inside select_for_update so
    two concurrent logins can't both succeed.

    SQLite serialises writes process-wide so a real thread race is hard to
    stage; the strongest evidence we can get in-test is:
      (a) the verify path is wrapped in transaction.atomic with select_for_update
      (b) sequential reuse of a recovery code is rejected
    """

    def test_recovery_code_single_use(self, auth_client, user):
        secret = _enable_2fa(auth_client, user)
        recovery = 'aaaa1111-bbbb2222'
        tf = TwoFactor.objects.get(user=user)
        tf.recovery_codes = [_hash_recovery(recovery)]
        tf.save()
        auth_client.logout()

        c = APIClient()
        r1 = c.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': recovery,
        }, format='json')
        assert r1.status_code == 200
        c.logout()

        # Same code is no longer valid.
        r2 = c.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': recovery,
        }, format='json')
        assert r2.status_code == 401

    def test_consumption_is_transactional(self):
        """A regression test that fails if someone removes the atomic wrapper."""
        import inspect
        from chat import twofactor
        src = inspect.getsource(twofactor.verify_for_login)
        assert 'transaction.atomic' in src
        assert 'select_for_update' in src


@pytest.mark.django_db
class TestLockout:
    """Finding #4: account-level brute-force lockout on TOTP failures."""

    def test_lockout_after_threshold(self, auth_client, client, user):
        _enable_2fa(auth_client, user)
        auth_client.logout()
        for _ in range(LOCKOUT_THRESHOLD):
            client.post('/api/auth/login/', {
                'username': user.username, 'password': 'Hunter2pass', 'code': '000000',
            }, format='json')
        tf = TwoFactor.objects.get(user=user)
        assert tf.failed_attempts >= LOCKOUT_THRESHOLD
        assert tf.locked_until is not None

    def test_correct_code_blocked_while_locked(self, auth_client, client, user):
        secret = _enable_2fa(auth_client, user)
        auth_client.logout()
        for _ in range(LOCKOUT_THRESHOLD):
            client.post('/api/auth/login/', {
                'username': user.username, 'password': 'Hunter2pass', 'code': '000000',
            }, format='json')
        TwoFactor.objects.filter(user=user).update(last_totp_step=0)
        # Even with a correct TOTP, login is denied while locked.
        r = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': pyotp.TOTP(secret).now(),
        }, format='json')
        assert r.status_code == 401

    def test_correct_code_resets_failures(self, auth_client, client, user):
        secret = _enable_2fa(auth_client, user)
        auth_client.logout()
        client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': '000000',
        }, format='json')
        # Reset replay tracking, then succeed with valid code.
        TwoFactor.objects.filter(user=user).update(last_totp_step=0)
        client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': pyotp.TOTP(secret).now(),
        }, format='json')
        tf = TwoFactor.objects.get(user=user)
        assert tf.failed_attempts == 0


@pytest.mark.django_db
class TestPasswordResetWith2FA:
    """Finding #1: password reset must NOT bypass 2FA."""

    def _seed_reset(self, client, user):
        client.post('/api/auth/forgot/', {'email': user.email}, format='json')
        body = mail.outbox[-1].body
        import re
        return re.search(r'\b(\d{6})\b', body).group(1)

    def test_reset_for_2fa_user_does_not_login(self, auth_client, client, user):
        _enable_2fa(auth_client, user)
        auth_client.logout()

        code = self._seed_reset(client, user)
        r = client.post('/api/auth/reset/', {
            'email': user.email, 'code': code, 'password': 'NewHunter2pass',
        }, format='json')
        assert r.status_code == 200
        body = r.json()
        # Must signal that 2FA is still required.
        assert body.get('two_factor_required') is True
        # Caller must not be logged in.
        me = client.get('/api/auth/me/').json()
        assert me['username'] is None

    def test_reset_revokes_existing_sessions(self, user):
        # Two active sessions for the user
        c1 = APIClient(); c1.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        c2 = APIClient(); c2.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        assert Session.objects.count() >= 2

        # Reset password from a fresh client
        c3 = APIClient()
        c3.post('/api/auth/forgot/', {'email': user.email}, format='json')
        import re
        otp = re.search(r'\b(\d{6})\b', mail.outbox[-1].body).group(1)
        r = c3.post('/api/auth/reset/', {
            'email': user.email, 'code': otp, 'password': 'NewHunter2pass',
        }, format='json')
        assert r.status_code == 200
        assert r.json().get('sessions_revoked', 0) >= 2

        # Old sessions are dead.
        assert c1.get('/api/auth/me/').json()['username'] is None
        assert c2.get('/api/auth/me/').json()['username'] is None

    def test_reset_for_non_2fa_user_logs_in(self, client, user):
        code = self._seed_reset(client, user)
        r = client.post('/api/auth/reset/', {
            'email': user.email, 'code': code, 'password': 'NewHunter2pass',
        }, format='json')
        assert r.status_code == 200
        assert r.json().get('two_factor_required', False) is False
        assert client.get('/api/auth/me/').json()['username'] == user.username


@pytest.mark.django_db
class TestSessionInvalidation:
    """Finding #5: revoke other sessions on sensitive auth changes."""

    def test_disable_revokes_other_sessions(self, user):
        c1 = APIClient(); c1.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        c2 = APIClient(); c2.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        # Enable 2FA from c1
        secret = _enable_2fa(c1, user)
        # Disable from c1 — c2 should die
        TwoFactor.objects.filter(user=user).update(last_totp_step=0)
        r = c1.post('/api/auth/2fa/disable/', {
            'password': 'Hunter2pass', 'code': pyotp.TOTP(secret).now(),
        }, format='json')
        assert r.status_code == 200
        assert r.json().get('sessions_revoked', 0) >= 1
        # c2 dead, c1 alive
        assert c2.get('/api/auth/me/').json()['username'] is None
        assert c1.get('/api/auth/me/').json()['username'] == user.username


@pytest.mark.django_db
class TestEditMessageRateLimit:
    """Finding #6: edit endpoint rate-limited."""

    def test_edit_rate_limited(self, auth_client, user, settings, convo):
        from chat.models import Message
        settings.RATELIMIT_ENABLE = True
        m = Message.objects.create(conversation=convo, role='user', content='hi')
        statuses = []
        for i in range(35):
            r = auth_client.patch(f'/api/messages/{m.id}/', {'content': f'edit {i}'}, format='json')
            statuses.append(r.status_code)
        assert 429 in statuses


@pytest.mark.django_db
class TestHoneypotOrdering:
    """Finding #9: honeypot fires only after validation, so malformed input
    looks the same with or without the trap field."""

    def test_invalid_input_returns_400_even_with_honeypot(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'a', 'email': 'bad', 'password': 'short',
            'website': 'http://spam.test',
        }, format='json')
        assert r.status_code == 400  # not 201

    def test_valid_input_with_honeypot_returns_fake_201(self, client):
        r = client.post('/api/auth/register/', {
            'username': 'goodbot', 'email': 'bot@example.com', 'password': 'GoodPassw0rd',
            'website': 'http://spam.test',
        }, format='json')
        assert r.status_code == 201
        # No user created
        from django.contrib.auth import get_user_model
        assert not get_user_model().objects.filter(username='goodbot').exists()
        assert mail.outbox == []


@pytest.mark.django_db
class TestAuditLog:
    """Finding #8: 2FA changes are logged."""

    def test_enroll_completion_logged(self, auth_client, user, caplog):
        import logging
        caplog.set_level(logging.INFO, logger='chat.twofactor')
        secret = auth_client.post('/api/auth/2fa/enroll/').json()['secret']
        auth_client.post('/api/auth/2fa/verify-enroll/', {'code': pyotp.TOTP(secret).now()}, format='json')
        assert any('2FA enabled' in r.message and str(user.pk) in r.message for r in caplog.records)

    def test_disable_logged(self, auth_client, user, caplog):
        import logging
        secret = _enable_2fa(auth_client, user)
        caplog.set_level(logging.INFO, logger='chat.twofactor')
        auth_client.post('/api/auth/2fa/disable/', {
            'password': 'Hunter2pass', 'code': pyotp.TOTP(secret).now(),
        }, format='json')
        assert any('2FA disabled' in r.message for r in caplog.records)
