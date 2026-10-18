"""Memory-hard password hashing and deferred-upgrade regressions."""

import pytest
from django.contrib.auth.hashers import (
    PBKDF2PasswordHasher,
    ScryptPasswordHasher,
    identify_hasher,
)
from django.test import override_settings
from rest_framework.test import APIClient

from chat.models import AuthenticatedSession, TwoFactor
from chat.twofactor import _hash_recovery
from nvidia_chat import settings as production_settings


MEMORY_HARD_HASHERS = [
    'django.contrib.auth.hashers.ScryptPasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
]
PASSWORD = 'Hunter2pass'
RECOVERY_CODE = 'aaaa1111-bbbb2222'


def _set_legacy_password(user):
    hasher = PBKDF2PasswordHasher()
    user.password = hasher.encode(PASSWORD, hasher.salt(), iterations=1)
    user.save(update_fields=['password'])
    return user.password


def test_production_prefers_memory_hard_scrypt():
    assert production_settings.PASSWORD_HASHERS[0] == (
        'django.contrib.auth.hashers.ScryptPasswordHasher'
    )
    assert 'django.contrib.auth.hashers.PBKDF2PasswordHasher' in (
        production_settings.PASSWORD_HASHERS
    )


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_new_passwords_use_scrypt_and_remain_verifiable(user):
    user.set_password(PASSWORD)
    user.save(update_fields=['password'])

    assert identify_hasher(user.password).algorithm == 'scrypt'
    assert ScryptPasswordHasher().verify(PASSWORD, user.password)


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_complete_login_upgrades_legacy_hash(client, user):
    _set_legacy_password(user)

    response = client.post('/api/auth/login/', {
        'username': user.username,
        'password': PASSWORD,
    }, format='json')

    assert response.status_code == 200
    user.refresh_from_db()
    assert identify_hasher(user.password).algorithm == 'scrypt'


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_wrong_password_does_not_upgrade_legacy_hash(client, user):
    original = _set_legacy_password(user)

    response = client.post('/api/auth/login/', {
        'username': user.username,
        'password': 'wrong-password',
    }, format='json')

    assert response.status_code == 401
    user.refresh_from_db()
    assert user.password == original


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_failed_login_still_emits_privacy_safe_security_event(client, user, caplog):
    _set_legacy_password(user)

    with caplog.at_level('WARNING', logger='security'):
        response = client.post('/api/auth/login/', {
            'username': user.username,
            'password': 'wrong-password',
        }, format='json')

    assert response.status_code == 401
    messages = [record.getMessage() for record in caplog.records]
    assert len([message for message in messages if message.startswith('event=auth_failed ')]) == 1
    assert PASSWORD not in caplog.text
    assert 'wrong-password' not in caplog.text


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_missing_second_factor_does_not_upgrade_or_invalidate_sessions(user):
    original = _set_legacy_password(user)
    TwoFactor.objects.create(
        user=user,
        secret='irrelevant',
        enabled=True,
        recovery_codes=[_hash_recovery(RECOVERY_CODE)],
    )
    existing = APIClient()
    existing.force_login(user)
    attempted = APIClient()

    response = attempted.post('/api/auth/login/', {
        'username': user.username,
        'password': PASSWORD,
    }, format='json')

    assert response.status_code == 401
    assert response.json()['two_factor_required'] is True
    user.refresh_from_db()
    assert user.password == original
    assert existing.get('/api/models/').status_code == 200


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_complete_two_factor_login_upgrades_legacy_hash(client, user):
    _set_legacy_password(user)
    TwoFactor.objects.create(
        user=user,
        secret='irrelevant',
        enabled=True,
        recovery_codes=[_hash_recovery(RECOVERY_CODE)],
    )

    response = client.post('/api/auth/login/', {
        'username': user.username,
        'password': PASSWORD,
        'code': RECOVERY_CODE,
    }, format='json')

    assert response.status_code == 200
    user.refresh_from_db()
    assert identify_hasher(user.password).algorithm == 'scrypt'
    assert TwoFactor.objects.get(user=user).recovery_codes == []


@pytest.mark.django_db
@override_settings(PASSWORD_HASHERS=MEMORY_HARD_HASHERS)
def test_complete_reauthentication_upgrades_and_preserves_current_session(user):
    _set_legacy_password(user)
    TwoFactor.objects.create(
        user=user,
        secret='irrelevant',
        enabled=True,
        recovery_codes=[_hash_recovery(RECOVERY_CODE)],
    )
    client = APIClient()
    client.force_login(user)

    missing = client.post('/api/auth/reauthenticate/', {
        'password': PASSWORD,
    }, format='json')
    user.refresh_from_db()
    assert missing.status_code == 401
    assert identify_hasher(user.password).algorithm == 'pbkdf2_sha256'

    accepted = client.post('/api/auth/reauthenticate/', {
        'password': PASSWORD,
        'code': RECOVERY_CODE,
    }, format='json')

    assert accepted.status_code == 200
    user.refresh_from_db()
    assert identify_hasher(user.password).algorithm == 'scrypt'
    assert client.get('/api/models/').status_code == 200
    assert AuthenticatedSession.objects.filter(
        user=user,
        session_id=client.session.session_key,
    ).exists()
