"""Tests for session listing + revocation."""
import pytest
from django.contrib.sessions.models import Session
from rest_framework.test import APIClient


def _login(user, password='Hunter2pass', ua='pytest-ua', ip='1.2.3.4'):
    """Real login through the endpoint so the session row gets UA/IP/login_at."""
    c = APIClient(HTTP_USER_AGENT=ua, REMOTE_ADDR=ip)
    r = c.post('/api/auth/login/', {'username': user.username, 'password': password}, format='json')
    assert r.status_code == 200, r.content
    return c


@pytest.mark.django_db
class TestListSessions:
    def test_lists_only_own_sessions(self, user, other_user):
        c1 = _login(user, ua='browser-A', ip='10.0.0.1')
        _login(user, ua='browser-B', ip='10.0.0.2')
        _login(other_user, ua='browser-C', ip='10.0.0.3')

        r = c1.get('/api/auth/sessions/')
        assert r.status_code == 200
        items = r.json()
        assert len(items) == 2
        uas = sorted(i['ua'] for i in items)
        assert uas == ['browser-A', 'browser-B']
        currents = [i for i in items if i['current']]
        assert len(currents) == 1 and currents[0]['ua'] == 'browser-A'

    def test_records_ip_and_login_at(self, user):
        c = _login(user, ua='UA1', ip='198.51.100.7')
        r = c.get('/api/auth/sessions/').json()
        s = r[0]
        assert s['ip'] == '198.51.100.7'
        assert s['ua'] == 'UA1'
        assert s['login_at'] is not None

    def test_unauthenticated_blocked(self, client):
        r = client.get('/api/auth/sessions/')
        assert r.status_code in (401, 403)


@pytest.mark.django_db
class TestRevokeSession:
    def test_revoke_other_session_logs_it_out(self, user):
        c1 = _login(user, ua='current')
        c2 = _login(user, ua='other')

        # c1 lists and finds the other session
        items = c1.get('/api/auth/sessions/').json()
        other = next(i for i in items if i['ua'] == 'other')
        r = c1.delete(f'/api/auth/sessions/{other["id"]}/')
        assert r.status_code == 204

        # c2 is now logged out
        me = c2.get('/api/auth/me/').json()
        assert me['username'] is None

        # c1 still works
        me1 = c1.get('/api/auth/me/').json()
        assert me1['username'] == user.username

    def test_cannot_revoke_current_via_revoke(self, user):
        c1 = _login(user, ua='current')
        my_key = c1.session.session_key
        r = c1.delete(f'/api/auth/sessions/{my_key}/')
        assert r.status_code == 400

    def test_cannot_revoke_other_users_session(self, user, other_user):
        # Other user has a session; current user must not be able to revoke it.
        c_other = _login(other_user, ua='theirs')
        their_key = c_other.session.session_key
        c_self = _login(user, ua='mine')
        r = c_self.delete(f'/api/auth/sessions/{their_key}/')
        assert r.status_code == 404
        # Their session still alive
        assert Session.objects.filter(session_key=their_key).exists()


@pytest.mark.django_db
class TestRevokeOthers:
    def test_revoke_others_kills_all_but_current(self, user):
        c_a = _login(user, ua='A')
        _login(user, ua='B')
        _login(user, ua='C')

        r = c_a.delete('/api/auth/sessions/revoke-others/')
        assert r.status_code == 200
        assert r.json()['revoked'] == 2

        # Only one session for the user remains
        items = c_a.get('/api/auth/sessions/').json()
        assert len(items) == 1
        assert items[0]['ua'] == 'A'

    def test_revoke_others_with_no_others(self, user):
        c = _login(user, ua='solo')
        r = c.delete('/api/auth/sessions/revoke-others/')
        assert r.status_code == 200
        assert r.json()['revoked'] == 0
