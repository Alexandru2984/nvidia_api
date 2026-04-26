"""Tests for optional TOTP 2FA: enroll, verify, login flow, disable, recovery."""
import pyotp
import pytest

from chat.models import TwoFactor
from chat.twofactor import _hash_recovery


@pytest.mark.django_db
class TestStatus:
    def test_default_disabled(self, auth_client):
        r = auth_client.get('/api/auth/2fa/status/')
        assert r.status_code == 200
        assert r.json()['enabled'] is False

    def test_unauthenticated_blocked(self, client):
        r = client.get('/api/auth/2fa/status/')
        assert r.status_code in (401, 403)


@pytest.mark.django_db
class TestEnroll:
    def test_enroll_returns_secret_and_qr(self, auth_client, user):
        r = auth_client.post('/api/auth/2fa/enroll/')
        assert r.status_code == 200
        body = r.json()
        assert 'secret' in body and len(body['secret']) >= 16
        assert body['provisioning_uri'].startswith('otpauth://totp/')
        assert body['qr_data_url'].startswith('data:image/svg+xml;base64,')
        # DB row created but not enabled until verified
        tf = TwoFactor.objects.get(user=user)
        assert tf.enabled is False

    def test_enroll_rotates_secret_each_call(self, auth_client):
        r1 = auth_client.post('/api/auth/2fa/enroll/').json()
        r2 = auth_client.post('/api/auth/2fa/enroll/').json()
        assert r1['secret'] != r2['secret']

    def test_enroll_blocked_when_already_enabled(self, auth_client, user):
        TwoFactor.objects.create(user=user, secret=pyotp.random_base32(), enabled=True)
        r = auth_client.post('/api/auth/2fa/enroll/')
        assert r.status_code == 409


@pytest.mark.django_db
class TestVerifyEnroll:
    def test_correct_code_enables_and_returns_recovery(self, auth_client, user):
        enrolled = auth_client.post('/api/auth/2fa/enroll/').json()
        code = pyotp.TOTP(enrolled['secret']).now()
        r = auth_client.post('/api/auth/2fa/verify-enroll/', {'code': code}, format='json')
        assert r.status_code == 200
        body = r.json()
        assert body['enabled'] is True
        assert len(body['recovery_codes']) == 10
        # Each recovery code looks like 'xxxxxxxx-xxxxxxxx'
        for rc in body['recovery_codes']:
            assert len(rc) == 17 and rc.count('-') == 1
        tf = TwoFactor.objects.get(user=user)
        assert tf.enabled is True
        # Stored hashes — never plaintext
        assert all(rc not in tf.recovery_codes for rc in body['recovery_codes'])

    def test_wrong_code_does_not_enable(self, auth_client, user):
        auth_client.post('/api/auth/2fa/enroll/')
        r = auth_client.post('/api/auth/2fa/verify-enroll/', {'code': '000000'}, format='json')
        assert r.status_code == 400
        assert TwoFactor.objects.get(user=user).enabled is False

    def test_must_call_enroll_first(self, auth_client):
        r = auth_client.post('/api/auth/2fa/verify-enroll/', {'code': '123456'}, format='json')
        assert r.status_code == 400


@pytest.mark.django_db
class TestLoginWith2FA:
    def _enable(self, auth_client):
        secret = auth_client.post('/api/auth/2fa/enroll/').json()['secret']
        auth_client.post(
            '/api/auth/2fa/verify-enroll/',
            {'code': pyotp.TOTP(secret).now()}, format='json',
        )
        return secret

    def test_login_without_code_returns_2fa_required(self, auth_client, client, user):
        self._enable(auth_client)
        client.logout()
        r = client.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        assert r.status_code == 401
        assert r.json().get('two_factor_required') is True

    def test_login_with_valid_code_succeeds(self, auth_client, client, user):
        secret = self._enable(auth_client)
        auth_client.logout()
        code = pyotp.TOTP(secret).now()
        r = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': code,
        }, format='json')
        assert r.status_code == 200
        assert r.json()['username'] == user.username

    def test_login_with_wrong_code_fails(self, auth_client, client, user):
        self._enable(auth_client)
        auth_client.logout()
        r = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': '000000',
        }, format='json')
        assert r.status_code == 401
        assert r.json().get('two_factor_required') is True

    def test_login_with_recovery_code_consumes_it(self, auth_client, client, user):
        self._enable(auth_client)
        # Use a recovery code by directly inserting a known one
        tf = TwoFactor.objects.get(user=user)
        plaintext = 'aaaa1111-bbbb2222'
        tf.recovery_codes = list(tf.recovery_codes) + [_hash_recovery(plaintext)]
        tf.save()
        original_count = len(tf.recovery_codes)
        auth_client.logout()
        r = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': plaintext,
        }, format='json')
        assert r.status_code == 200
        tf.refresh_from_db()
        assert len(tf.recovery_codes) == original_count - 1
        # Same recovery code can't be reused
        client.logout()
        r2 = client.post('/api/auth/login/', {
            'username': user.username, 'password': 'Hunter2pass', 'code': plaintext,
        }, format='json')
        assert r2.status_code == 401

    def test_login_for_user_without_2fa_unchanged(self, client, user):
        # Pre-existing path still works for non-2FA users.
        r = client.post('/api/auth/login/', {'username': user.username, 'password': 'Hunter2pass'}, format='json')
        assert r.status_code == 200


@pytest.mark.django_db
class TestDisable:
    def test_disable_requires_password_and_code(self, auth_client, user):
        secret = auth_client.post('/api/auth/2fa/enroll/').json()['secret']
        auth_client.post('/api/auth/2fa/verify-enroll/', {'code': pyotp.TOTP(secret).now()}, format='json')

        # Wrong password
        r = auth_client.post('/api/auth/2fa/disable/', {
            'password': 'wrong', 'code': pyotp.TOTP(secret).now(),
        }, format='json')
        assert r.status_code == 401

        # Right password, wrong code
        r = auth_client.post('/api/auth/2fa/disable/', {
            'password': 'Hunter2pass', 'code': '000000',
        }, format='json')
        assert r.status_code == 401

        # Right password + correct code
        r = auth_client.post('/api/auth/2fa/disable/', {
            'password': 'Hunter2pass', 'code': pyotp.TOTP(secret).now(),
        }, format='json')
        assert r.status_code == 200
        assert not TwoFactor.objects.filter(user=user).exists()


@pytest.mark.django_db
class TestRegenerateRecoveryCodes:
    def test_regenerate_invalidates_old(self, auth_client, user):
        secret = auth_client.post('/api/auth/2fa/enroll/').json()['secret']
        first = auth_client.post(
            '/api/auth/2fa/verify-enroll/',
            {'code': pyotp.TOTP(secret).now()}, format='json',
        ).json()['recovery_codes']

        # Wrong code blocked
        r = auth_client.post('/api/auth/2fa/recovery-codes/', {'code': '000000'}, format='json')
        assert r.status_code == 401

        # With valid TOTP, returns 10 new codes
        r = auth_client.post(
            '/api/auth/2fa/recovery-codes/',
            {'code': pyotp.TOTP(secret).now()}, format='json',
        )
        assert r.status_code == 200
        new_codes = r.json()['recovery_codes']
        assert len(new_codes) == 10
        assert set(new_codes).isdisjoint(first)
