"""Fresh-authentication boundaries for sensitive session operations."""
import pytest
from django.conf import settings
from django.contrib.sessions.models import Session
from rest_framework.test import APIClient

from chat.models import TwoFactor
from chat.twofactor import _hash_recovery


def _login(user, *, ua='pytest-recent-auth'):
    client = APIClient(HTTP_USER_AGENT=ua)
    response = client.post('/api/auth/login/', {
        'username': user.username,
        'password': 'Hunter2pass',
    }, format='json')
    assert response.status_code == 200
    return client


def _expire_marker(client, seconds=None):
    session = client.session
    marker = session['recent_authentication']
    marker['authenticated_at'] -= seconds or settings.RECENT_AUTH_MAX_AGE_SECONDS + 1
    session['recent_authentication'] = marker
    session.save()


@pytest.mark.django_db
class TestRecentAuthentication:
    def test_complete_login_marks_session_as_recent(self, user):
        client = _login(user)

        marker = client.session['recent_authentication']
        assert marker['user_id'] == str(user.pk)
        assert isinstance(marker['authenticated_at'], int)
        assert len(marker['credential']) == 64
        assert marker['credential'] != user.password

    def test_reauthentication_requires_an_authenticated_session(self, client):
        response = client.post('/api/auth/reauthenticate/', {
            'password': 'Hunter2pass',
        }, format='json')

        assert response.status_code in (401, 403)

    def test_old_forced_session_cannot_revoke_sessions(self, user):
        old = APIClient()
        old.force_login(user)
        other = _login(user, ua='other')
        other_key = other.session.session_key

        response = old.delete('/api/auth/sessions/revoke-others/')

        assert response.status_code == 403
        assert response.json()['reauthentication_required'] is True
        assert Session.objects.filter(session_key=other_key).exists()

    def test_expired_marker_requires_reauthentication_then_retries(self, user):
        current = _login(user, ua='current')
        other = _login(user, ua='other')
        other_key = other.session.session_key
        _expire_marker(current)

        blocked = current.delete('/api/auth/sessions/revoke-others/')
        refreshed = current.post('/api/auth/reauthenticate/', {
            'password': 'Hunter2pass',
        }, format='json')
        revoked = current.delete('/api/auth/sessions/revoke-others/')

        assert blocked.status_code == 403
        assert refreshed.status_code == 200
        assert refreshed.json()['valid_for_seconds'] == settings.RECENT_AUTH_MAX_AGE_SECONDS
        assert revoked.status_code == 200
        assert revoked.json()['revoked'] == 1
        assert not Session.objects.filter(session_key=other_key).exists()

    def test_wrong_password_does_not_refresh_marker(self, user):
        client = APIClient()
        client.force_login(user)

        response = client.post('/api/auth/reauthenticate/', {
            'password': 'wrong',
        }, format='json')

        assert response.status_code == 401
        assert 'recent_authentication' not in client.session

    def test_two_factor_is_required_and_recovery_code_is_consumed(self, user):
        recovery = 'aaaa1111-bbbb2222'
        TwoFactor.objects.create(
            user=user,
            secret='irrelevant',
            enabled=True,
            recovery_codes=[_hash_recovery(recovery)],
        )
        client = APIClient()
        client.force_login(user)

        missing = client.post('/api/auth/reauthenticate/', {
            'password': 'Hunter2pass',
        }, format='json')
        accepted = client.post('/api/auth/reauthenticate/', {
            'password': 'Hunter2pass',
            'code': recovery,
        }, format='json')

        assert missing.status_code == 401
        assert missing.json()['two_factor_required'] is True
        assert accepted.status_code == 200
        assert TwoFactor.objects.get(user=user).recovery_codes == []
        assert 'recent_authentication' in client.session

    def test_future_marker_is_rejected(self, user):
        client = _login(user)
        session = client.session
        marker = session['recent_authentication']
        marker['authenticated_at'] += settings.RECENT_AUTH_MAX_AGE_SECONDS + 60
        session['recent_authentication'] = marker
        session.save()

        response = client.delete('/api/auth/sessions/revoke-others/')

        assert response.status_code == 403
        assert 'recent_authentication' not in client.session

    def test_marker_never_extends_absolute_session_deadline(self, user):
        client = _login(user)
        absolute_before = client.session['absolute_expires_at']
        _expire_marker(client)

        response = client.post('/api/auth/reauthenticate/', {
            'password': 'Hunter2pass',
        }, format='json')

        assert response.status_code == 200
        assert client.session['absolute_expires_at'] == absolute_before
