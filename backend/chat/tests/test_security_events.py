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


@pytest.mark.django_db
def test_security_success_waits_for_outer_commit(django_capture_on_commit_callbacks):
    from django.db import transaction
    from chat.security_events import log_committed_security_event

    with mock.patch('chat.security_events.security_log.warning') as warning:
        with django_capture_on_commit_callbacks(execute=True):
            with transaction.atomic():
                log_committed_security_event('event=two_factor_enabled user_id=%s', 123)
            warning.assert_not_called()
        warning.assert_called_once_with('event=two_factor_enabled user_id=%s', 123)


@pytest.mark.django_db
def test_rolled_back_security_change_is_not_reported(django_capture_on_commit_callbacks):
    from django.db import transaction
    from chat.security_events import log_committed_security_event

    with mock.patch('chat.security_events.security_log.warning') as warning:
        with django_capture_on_commit_callbacks(execute=True):
            with pytest.raises(RuntimeError):
                with transaction.atomic():
                    log_committed_security_event('event=password_changed user_id=%s', 123)
                    raise RuntimeError('synthetic transaction failure')
        warning.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize('with_factor', [False, True])
def test_password_reset_reports_only_committed_numeric_metadata(
    auth_client, user, with_factor, caplog, django_capture_on_commit_callbacks,
):
    from datetime import timedelta
    import pyotp
    from django.utils import timezone
    from chat.models import PasswordReset, TwoFactor
    from chat.twofactor import _encrypt_secret
    from chat.views import _hash_code

    if with_factor:
        TwoFactor.objects.create(user=user, secret=_encrypt_secret(pyotp.random_base32()), enabled=True)
    PasswordReset.objects.create(
        user=user, code_hash=_hash_code('123456'),
        sent_at=timezone.now(),
        expires_at=timezone.now() + timedelta(minutes=10),
    )
    with caplog.at_level('WARNING', logger='security'):
        with django_capture_on_commit_callbacks(execute=True):
            response = auth_client.post('/api/auth/reset/', {
                'email': user.email, 'code': '123456', 'password': 'DifferentSafePassword1!',
            }, format='json')
            assert 'event=password_reset_completed' not in caplog.text
    assert response.status_code == 200
    assert bool(response.json().get('two_factor_required')) is with_factor
    user.refresh_from_db()
    assert user.check_password('DifferentSafePassword1!')
    if with_factor:
        assert TwoFactor.objects.get(user=user).enabled
        assert auth_client.get('/api/auth/me/').json()['username'] is None
    else:
        assert auth_client.get('/api/auth/me/').json()['username'] == user.username
    assert 'event=password_reset_completed user_id=' in caplog.text
    for private in (user.email, '123456', 'DifferentSafePassword1!'):
        assert private not in caplog.text
