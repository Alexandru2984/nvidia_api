"""Credential proofs, mutations and session updates share one transaction."""
from unittest.mock import patch

import pyotp
import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.contrib.sessions.models import Session

from chat.models import TwoFactor
from chat.twofactor import _encrypt_secret, _hash_recovery


PASSWORD = 'Hunter2pass'
RECOVERY = 'aaaa1111-bbbb2222'
pytestmark = pytest.mark.django_db


def test_enrollment_session_failure_rolls_back_factor_activation(auth_client, user):
    setup = auth_client.post('/api/auth/2fa/enroll/', {'password': PASSWORD}, format='json')
    assert setup.status_code == 200
    secret = setup.json()['secret']
    with patch('chat.twofactor._rotate_and_revoke_other_sessions', side_effect=RuntimeError('injected failure')):
        with pytest.raises(RuntimeError, match='injected failure'):
            auth_client.post('/api/auth/2fa/verify-enroll/', {
                'code': pyotp.TOTP(secret).now(),
            }, format='json')

    factor = TwoFactor.objects.get(user=user)
    assert factor.enabled is False
    assert factor.recovery_codes == []
    assert factor.last_totp_step == 0


@pytest.mark.parametrize('action', ['disable', 'recovery-codes'])
def test_factor_session_failure_restores_factor_and_consumed_code(auth_client, user, action):
    factor = TwoFactor.objects.create(
        user=user, secret=_encrypt_secret(pyotp.random_base32()), enabled=True,
        recovery_codes=[_hash_recovery(RECOVERY)],
    )
    original_codes = factor.recovery_codes[:]
    with patch('chat.twofactor._rotate_and_revoke_other_sessions', side_effect=RuntimeError('injected failure')):
        with pytest.raises(RuntimeError, match='injected failure'):
            auth_client.post(f'/api/auth/2fa/{action}/', {
                'password': PASSWORD, 'code': RECOVERY,
            }, format='json')

    factor.refresh_from_db()
    assert factor.enabled is True
    assert factor.recovery_codes == original_codes
    assert factor.last_used_at is None


def test_password_session_failure_restores_password_and_session(auth_client, user):
    original_password = user.password
    original_session = auth_client.session.session_key
    with patch('chat.views.sync_session_record', side_effect=RuntimeError('injected failure')):
        with pytest.raises(RuntimeError, match='injected failure'):
            auth_client.post('/api/auth/password/', {
                'current_password': PASSWORD, 'new_password': 'DifferentSafePassword1!',
            }, format='json')

    user.refresh_from_db()
    assert user.password == original_password
    assert Session.objects.filter(session_key=original_session).exists()


@pytest.mark.parametrize('change', ['inactive', 'password'])
@pytest.mark.parametrize('endpoint,payload', [
    ('/api/auth/reauthenticate/', {'password': PASSWORD}),
    ('/api/auth/2fa/enroll/', {'password': PASSWORD}),
    ('/api/auth/2fa/verify-enroll/', {'code': '123456'}),
    ('/api/auth/2fa/disable/', {'password': PASSWORD}),
    ('/api/auth/2fa/recovery-codes/', {'password': PASSWORD}),
    ('/api/auth/password/', {'current_password': PASSWORD, 'new_password': 'AnotherSafePassword1!'}),
    ('/api/auth/delete-account/', {'password': PASSWORD}),
    ('/api/account/deletion/', {'password': PASSWORD}),
])
def test_stale_authenticated_account_is_rejected(client, user, change, endpoint, payload):
    # Model a request authenticated before another request reset/deactivated the
    # account: DRF still holds the old User instance when it reaches the view.
    client.force_authenticate(user=user)
    updates = {'is_active': False} if change == 'inactive' else {
        'password': make_password('PasswordChangedElsewhere1!'),
    }
    get_user_model().objects.filter(pk=user.pk).update(**updates)

    response = client.post(endpoint, payload, format='json')

    assert response.status_code == 401
    assert get_user_model().objects.filter(pk=user.pk).exists()


def test_reauthentication_rechecks_factor_requirement_after_account_lock(auth_client):
    # A factor was absent at the preliminary read and enabled before the lock
    # was acquired. The post-lock decision must require its code.
    with patch('chat.twofactor.login_requires_2fa', side_effect=[False, True]):
        response = auth_client.post('/api/auth/reauthenticate/', {
            'password': PASSWORD,
        }, format='json')

    assert response.status_code == 401
    assert response.json()['two_factor_required'] is True
