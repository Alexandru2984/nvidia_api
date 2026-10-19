import pyotp
import pytest
from rest_framework.test import APIClient

from chat.models import AdminAuditEvent, TwoFactor
from chat.recent_auth import RECENT_AUTH_SESSION_KEY
from chat.twofactor import STAFF_2FA_SESSION_KEY

pytestmark = pytest.mark.django_db


def _make_staff(user):
    user.is_staff = True
    user.is_superuser = True
    user.save(update_fields=['is_staff', 'is_superuser'])


def _enroll(client):
    secret = client.post(
        '/api/auth/2fa/enroll/',
        {'password': 'Hunter2pass'},
        format='json',
    ).json()['secret']
    response = client.post(
        '/api/auth/2fa/verify-enroll/',
        {'code': pyotp.TOTP(secret).now()},
        format='json',
    )
    assert response.status_code == 200
    return response.json()['recovery_codes']


def _expire_recent_auth(client):
    session = client.session
    marker = session[RECENT_AUTH_SESSION_KEY]
    marker['authenticated_at'] = 0
    session[RECENT_AUTH_SESSION_KEY] = marker
    session.save()


def test_anonymous_admin_login_form_is_not_exposed(client):
    response = client.get('/admin/login/')
    assert response.status_code == 403
    assert b'2FA verified through the main application' in response.content


def test_staff_without_two_factor_cannot_access_admin(auth_client, user):
    _make_staff(user)
    assert auth_client.get('/admin/').status_code == 403


def test_staff_enrollment_marks_current_session_for_admin(auth_client, user):
    _make_staff(user)
    _enroll(auth_client)
    assert auth_client.session[STAFF_2FA_SESSION_KEY] == str(user.pk)
    assert auth_client.get('/admin/').status_code == 200


def test_enabled_factor_without_session_verification_is_denied(auth_client, user):
    _make_staff(user)
    _enroll(auth_client)
    fresh = APIClient()
    fresh.force_login(user)
    assert fresh.get('/admin/').status_code == 403


def test_main_login_with_recovery_code_unlocks_staff_admin(auth_client, user):
    _make_staff(user)
    recovery_codes = _enroll(auth_client)
    auth_client.logout()

    fresh = APIClient()
    response = fresh.post('/api/auth/login/', {
        'username': user.username,
        'password': 'Hunter2pass',
        'code': recovery_codes[0],
    }, format='json')
    assert response.status_code == 200
    assert fresh.get('/admin/').status_code == 200
    assert TwoFactor.objects.get(user=user).enabled is True


def test_expired_staff_window_redirects_get_to_responsive_step_up(auth_client, user):
    _make_staff(user)
    _enroll(auth_client)
    _expire_recent_auth(auth_client)

    response = auth_client.get('/admin/?next=https://attacker.invalid/')

    assert response.status_code == 302
    assert response['Location'] == '/?admin_reauth=1&next=%2Fadmin%2F'
    assert 'admin_access_logged' not in auth_client.session


def test_expired_staff_window_denies_mutation_without_redirect(auth_client, user, convo):
    _make_staff(user)
    _enroll(auth_client)
    _expire_recent_auth(auth_client)

    response = auth_client.post(f'/admin/chat/conversation/{convo.pk}/change/', {
        'user': user.pk,
        'title': 'must not be saved',
        'model_id': convo.model_id,
        'system_prompt': '',
        'temperature': '0.7',
        'max_tokens': '1024',
        '_save': 'Save',
    })

    assert response.status_code == 403
    convo.refresh_from_db()
    assert convo.title != 'must not be saved'
    assert AdminAuditEvent.objects.count() == 0


def test_admin_step_up_requires_password_and_second_factor(auth_client, user):
    _make_staff(user)
    recovery_codes = _enroll(auth_client)
    _expire_recent_auth(auth_client)

    missing = auth_client.post('/api/auth/admin-reauthenticate/', {
        'password': 'Hunter2pass',
    }, format='json')
    assert missing.status_code == 401
    assert missing.json()['two_factor_required'] is True

    accepted = auth_client.post('/api/auth/admin-reauthenticate/', {
        'password': 'Hunter2pass',
        'code': recovery_codes[0],
    }, format='json')
    assert accepted.status_code == 200
    assert accepted.json()['valid_for_seconds'] == 300
    assert auth_client.get('/admin/').status_code == 200


def test_admin_step_up_is_generic_for_nonstaff(auth_client):
    response = auth_client.post('/api/auth/admin-reauthenticate/', {
        'password': 'Hunter2pass',
        'code': '123456',
    }, format='json')

    assert response.status_code == 403
    assert response.json() == {'error': 'Admin access is unavailable.'}


def test_expired_staff_can_still_log_out_of_admin(auth_client, user):
    _make_staff(user)
    _enroll(auth_client)
    _expire_recent_auth(auth_client)

    response = auth_client.post('/admin/logout/')

    assert response.status_code == 200
    assert '_auth_user_id' not in auth_client.session


def test_admin_guard_does_not_affect_normal_api(auth_client):
    assert auth_client.get('/api/account/usage/').status_code == 200


def test_verified_admin_change_creates_privacy_safe_audit(auth_client, user, convo):
    _make_staff(user)
    _enroll(auth_client)
    response = auth_client.post(f'/admin/chat/conversation/{convo.pk}/change/', {
        'user': user.pk,
        'title': 'updated private title',
        'model_id': convo.model_id,
        'system_prompt': '',
        'temperature': '0.7',
        'max_tokens': '1024',
        '_save': 'Save',
    })

    assert response.status_code == 302
    event = AdminAuditEvent.objects.get()
    assert event.action == 'change'
    assert event.model_label == 'chat.conversation'
    assert event.object_ref == str(convo.pk)
    assert 'updated private title' not in str(event.changed_fields)
