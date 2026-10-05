from unittest import mock

import pytest
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.test import RequestFactory

from chat.security_events import actor_for_request
from chat.views import _rate_limited


def test_actor_fingerprint_does_not_expose_raw_ip(settings):
    request = RequestFactory().get('/', REMOTE_ADDR='203.0.113.55')
    actor = actor_for_request(request)
    assert actor.startswith('network:')
    assert '203.0.113.55' not in actor


def test_failed_login_emits_structured_privacy_safe_event():
    request = RequestFactory().post('/api/auth/login/', REMOTE_ADDR='203.0.113.55')
    with mock.patch('chat.security_events.security_log.warning') as warning:
        user_login_failed.send(
            sender=object, credentials={'username': 'not-logged'}, request=request,
        )
    message, actor = warning.call_args.args
    assert message == 'event=auth_failed actor=%s'
    assert actor.startswith('network:')
    assert '203.0.113.55' not in actor


@pytest.mark.django_db
def test_admin_login_emits_high_signal_event(user):
    request = RequestFactory().post('/admin/login/')
    with mock.patch('chat.security_events.security_log.warning') as warning:
        user_logged_in.send(sender=user.__class__, request=request, user=user)
    warning.assert_called_once_with('event=admin_login user_id=%s', user.pk)


def test_rate_limit_emits_path_and_fingerprinted_actor():
    request = RequestFactory().post('/api/auth/login/', REMOTE_ADDR='203.0.113.55')
    request.limited = True
    with mock.patch('chat.views.security_log.warning') as warning:
        response = _rate_limited(request)
    assert response.status_code == 429
    message, path, actor = warning.call_args.args
    assert message == 'event=rate_limit path=%s actor=%s'
    assert path == '/api/auth/login/'
    assert actor.startswith('network:')
    assert '203.0.113.55' not in actor
