"""SMTP admission, SQL-failure independence and private filesystem boundaries."""
import json
import multiprocessing
import os
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timedelta, timezone as utc
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.utils import timezone

from chat.auth_mail import (
    AuthMailLimited, AuthMailUnavailable, check_auth_mail_budget,
    reserve_auth_mail,
)
from chat.cache import AtomicFileCache
from chat.models import EmailVerification, PasswordReset, RegistrationInvite
from chat.registration import generate_invite_code, hash_invite_code


def _state(settings):
    return json.loads((Path(settings.AUTH_MAIL_BUDGET_DIR) / 'state.json').read_text())


def test_recipient_limit_combines_email_kinds_without_storing_addresses(settings):
    settings.AUTH_MAIL_RECIPIENT_DAILY_LIMIT = 2
    reserve_auth_mail('Private@example.com', 'verification')
    reserve_auth_mail('private@EXAMPLE.COM', 'reset')
    with pytest.raises(AuthMailLimited):
        reserve_auth_mail('private@example.com', 'reset')
    value = _state(settings)
    assert value['verification'] == value['reset'] == 1
    assert list(value['recipients'].values()) == [2]
    assert 'example.com' not in json.dumps(value)


def test_verification_budget_does_not_consume_reset_allowance(settings):
    settings.AUTH_MAIL_VERIFICATION_DAILY_LIMIT = 1
    settings.AUTH_MAIL_RESET_DAILY_LIMIT = 1
    reserve_auth_mail('one@example.com', 'verification')
    with pytest.raises(AuthMailLimited):
        reserve_auth_mail('two@example.com', 'verification')
    reserve_auth_mail('two@example.com', 'reset')
    assert _state(settings)['reset'] == 1


def test_cache_culling_and_clear_do_not_refund_mail_attempts(settings):
    settings.AUTH_MAIL_RESET_DAILY_LIMIT = 1
    reserve_auth_mail('one@example.com', 'reset')
    cache = AtomicFileCache(str(Path(settings.AUTH_MAIL_BUDGET_DIR).parent), {
        'OPTIONS': {'MAX_ENTRIES': 1, 'CULL_FREQUENCY': 0},
    })
    cache.set('one', 1)
    cache.set('two', 2)
    cache.clear()
    with pytest.raises(AuthMailLimited):
        reserve_auth_mail('two@example.com', 'reset')


@pytest.mark.django_db
def test_failed_smtp_attempts_remain_charged_after_sql_rollback(client, user, settings, caplog):
    settings.AUTH_MAIL_RESET_DAILY_LIMIT = 2
    responses = []
    with patch('chat.views._send_password_reset_email', side_effect=RuntimeError(
        'private-smtp-marker recipient=alice@example.com code=123456',
    )) as sender:
        with caplog.at_level('ERROR'):
            for index in range(3):
                responses.append(client.post('/api/auth/forgot/', {'email': user.email},
                    format='json', REMOTE_ADDR=f'198.51.100.{index + 1}'))
    assert sender.call_count == 2
    assert len({json.dumps(r.json(), sort_keys=True) for r in responses}) == 1
    assert all(r.status_code == 200 for r in responses)
    assert not PasswordReset.objects.exists()
    assert _state(settings)['reset'] == 2
    assert 'private-smtp-marker' not in caplog.text
    assert 'alice@example.com' not in caplog.text
    assert '123456' not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.django_db
def test_exhaustion_response_does_not_reveal_account_existence(client, user, other_user, settings):
    settings.AUTH_MAIL_RESET_DAILY_LIMIT = 1
    first = client.post('/api/auth/forgot/', {'email': user.email}, format='json')
    blocked = client.post('/api/auth/forgot/', {'email': other_user.email}, format='json')
    absent = client.post('/api/auth/forgot/', {'email': 'absent@example.com'}, format='json')
    assert first.json() == blocked.json() == absent.json()
    assert first.status_code == blocked.status_code == absent.status_code == 200
    assert len(mail.outbox) == 1
    assert not PasswordReset.objects.filter(user=other_user).exists()


@pytest.mark.django_db
def test_registration_budget_preserves_invitation_on_rejection(client, settings):
    settings.REGISTRATION_MODE = 'invite'
    settings.AUTH_MAIL_VERIFICATION_DAILY_LIMIT = 0
    raw = generate_invite_code()
    invitation = RegistrationInvite.objects.create(
        code_hash=hash_invite_code(raw), expires_at=timezone.now() + timedelta(days=1),
    )
    with patch.object(get_user_model(), 'set_password') as hasher:
        response = client.post('/api/auth/register/', {
            'username': 'newuser', 'email': 'new@example.com', 'password': 'SafePassw0rd!',
            'invite_code': raw,
        }, format='json')
        hasher.assert_not_called()
    assert response.status_code == 201
    assert not get_user_model().objects.filter(username='newuser').exists()
    assert not EmailVerification.objects.exists()
    invitation.refresh_from_db()
    assert invitation.used_at is None
    assert mail.outbox == []


@pytest.mark.django_db
def test_resend_budget_preserves_existing_code(client, settings):
    settings.AUTH_MAIL_RECIPIENT_DAILY_LIMIT = 1
    response = client.post('/api/auth/register/', {
        'username': 'newuser', 'email': 'new@example.com', 'password': 'SafePassw0rd!',
    }, format='json')
    assert response.status_code == 201
    original = EmailVerification.objects.get()
    EmailVerification.objects.filter(pk=original.pk).update(sent_at=timezone.now() - timedelta(minutes=2))
    response = client.post('/api/auth/resend/', {'email': 'new@example.com'}, format='json')
    assert response.status_code == 200
    assert len(mail.outbox) == 1
    assert EmailVerification.objects.get().code_hash == original.code_hash


@pytest.mark.django_db
@pytest.mark.parametrize('flow', ['register', 'resend', 'forgot'])
@pytest.mark.parametrize('failure', ['exception', 'zero_deliveries'])
def test_all_mail_failure_paths_keep_private_details_out_of_logs(client, user, caplog, flow, failure):
    if flow == 'register':
        data = {'username': 'newuser', 'email': 'new@example.com', 'password': 'SafePassw0rd!'}
    else:
        if flow == 'resend':
            user.is_active = False
            user.save(update_fields=['is_active'])
        data = {'email': user.email}
    options = ({'side_effect': RuntimeError('private-smtp-marker alice@example.com code=123456')}
               if failure == 'exception' else {'return_value': 0})
    with patch('chat.views.EmailMultiAlternatives.send', **options):
        with caplog.at_level('ERROR', logger='security'):
            response = client.post(f'/api/auth/{flow}/', data, format='json')
    assert response.status_code == (201 if flow == 'register' else 200)
    assert 'event=auth_mail_delivery_failed' in caplog.text
    for private in ('private-smtp-marker', 'alice@example.com', '123456'):
        assert private not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    assert not PasswordReset.objects.exists()
    assert not EmailVerification.objects.exists()
    if flow == 'register':
        assert not get_user_model().objects.filter(username='newuser').exists()


@pytest.mark.parametrize('boundary', ['corrupt', 'broad_mode', 'link', 'fifo', 'future', 'oversized'])
def test_unsafe_budget_fails_closed_without_private_error_text(settings, tmp_path, boundary, caplog):
    check_auth_mail_budget()
    path = Path(settings.AUTH_MAIL_BUDGET_DIR) / 'state.json'
    if boundary == 'corrupt':
        path.write_text('private-state-marker')
    elif boundary == 'broad_mode':
        path.chmod(0o644)
    elif boundary == 'link':
        target = tmp_path / 'private-target'
        target.write_text('private-state-marker')
        path.unlink()
        path.symlink_to(target)
    elif boundary == 'fifo':
        path.unlink()
        os.mkfifo(path, 0o600)
    elif boundary == 'future':
        value = _state(settings)
        value['day'] = '2999-01-01'
        path.write_text(json.dumps(value))
    else:
        path.write_bytes(b'x' * (32 * 1024 + 1))
    with caplog.at_level('ERROR', logger='security'):
        with pytest.raises(AuthMailUnavailable):
            reserve_auth_mail('private@example.com', 'reset')
    assert 'event=auth_mail_budget_unavailable' in caplog.text
    assert 'private-state-marker' not in caplog.text
    assert 'private@example.com' not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    if boundary == 'link':
        assert target.read_text() == 'private-state-marker'


@pytest.mark.django_db
def test_daily_expiry_removes_old_recipient_hashes_but_dry_run_does_not(settings):
    with patch('chat.auth_mail.datetime') as clock:
        clock.now.return_value = datetime(2026, 1, 1, tzinfo=utc.utc)
        reserve_auth_mail('one@example.com', 'reset')
        old = _state(settings)
        clock.now.return_value = datetime(2026, 1, 2, tzinfo=utc.utc)
        call_command('cleanup_attachments', '--dry-run', stdout=StringIO())
        assert _state(settings) == old
        call_command('cleanup_attachments', stdout=StringIO())
    assert _state(settings)['recipients'] == {}
    assert _state(settings)['reset'] == 0
    assert _state(settings)['day'] == '2026-01-02'


def test_checker_does_not_consume_delivery_allowance(settings):
    reserve_auth_mail('one@example.com', 'verification')
    before = _state(settings)
    call_command('check_auth_mail_budget', stdout=StringIO())
    assert _state(settings) == before


def test_checker_reclaims_crash_snapshot_without_refunding_allowance(settings):
    reserve_auth_mail('one@example.com', 'verification')
    before = _state(settings)
    root = Path(settings.AUTH_MAIL_BUDGET_DIR)
    temporary = root / '.state-crash'
    temporary.write_text(json.dumps(before))
    temporary.chmod(0o600)

    call_command('check_auth_mail_budget', stdout=StringIO())

    assert not temporary.exists()
    assert _state(settings) == before


def test_crash_snapshot_cleanup_refuses_symlink_without_touching_target(settings, tmp_path):
    check_auth_mail_budget()
    target = tmp_path / 'private-sentinel'
    target.write_bytes(b'keep')
    (Path(settings.AUTH_MAIL_BUDGET_DIR) / '.state-crash').symlink_to(target)

    with pytest.raises(AuthMailUnavailable):
        reserve_auth_mail('one@example.com', 'verification')

    assert target.read_bytes() == b'keep'


def _parallel_mail_attempts(index):
    allowed = 0
    for _ in range(20):
        try:
            reserve_auth_mail(f'worker{index}@example.com', 'reset')
            allowed += 1
        except AuthMailLimited:
            pass
    return allowed


def test_budget_is_atomic_across_worker_processes(settings):
    settings.AUTH_MAIL_RESET_DAILY_LIMIT = 7
    settings.AUTH_MAIL_RECIPIENT_DAILY_LIMIT = 100
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('fork')) as workers:
        counts = list(workers.map(_parallel_mail_attempts, range(4)))
    assert sum(counts) == 7
    assert _state(settings)['reset'] == 7
    assert sum(_state(settings)['recipients'].values()) == 7
