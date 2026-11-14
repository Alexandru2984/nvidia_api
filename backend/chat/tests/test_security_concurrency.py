"""Real PostgreSQL interleavings for account-security operations.

Run with scripts/test_postgres_security.sh; SQLite has no row-lock semantics.
"""
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pyotp
import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.db import connection, connections, transaction
from rest_framework.test import APIClient

from chat import twofactor
from chat.models import TwoFactor


pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(connection.vendor != 'postgresql', reason='requires PostgreSQL row locks'),
]
PASSWORD = 'Hunter2pass'


def _worker(callback):
    try:
        return callback()
    finally:
        connections.close_all()


def _wait_for_lock_or_completion(future):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if future.done():
            return False
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid() "
                "AND wait_event_type = 'Lock'",
            )
            if cursor.fetchone()[0]:
                return True
        threading.Event().wait(0.02)
    raise AssertionError('concurrent operation neither completed nor waited for a lock')


def test_enrollment_cannot_be_overtaken_by_factor_activation(user):
    completing = APIClient()
    completing.force_login(user)
    pending = completing.post('/api/auth/2fa/enroll/', {'password': PASSWORD}, format='json')
    assert pending.status_code == 200
    secret = pending.json()['secret']
    restarting = APIClient()
    restarting.force_login(user)
    checked_disabled = threading.Event()
    release = threading.Event()
    original_confirm = twofactor.confirm_recent_auth

    def pause_after_enabled_check(*args, **kwargs):
        checked_disabled.set()
        if not release.wait(10):
            raise AssertionError('test did not release enrollment')
        return original_confirm(*args, **kwargs)

    with ThreadPoolExecutor(max_workers=2) as executor:
        with patch('chat.twofactor.confirm_recent_auth', side_effect=pause_after_enabled_check):
            restarting_call = executor.submit(_worker, lambda: restarting.post(
                '/api/auth/2fa/enroll/', {'password': PASSWORD}, format='json',
            ))
            try:
                assert checked_disabled.wait(5)
                completing_call = executor.submit(_worker, lambda: completing.post(
                    '/api/auth/2fa/verify-enroll/',
                    {'code': pyotp.TOTP(secret).now()}, format='json',
                ))
                blocked = _wait_for_lock_or_completion(completing_call)
            finally:
                release.set()
            restarted = restarting_call.result(timeout=10)
            completed = completing_call.result(timeout=10)

    assert blocked, 'factor activation overtook an in-flight enrollment'
    assert restarted.status_code == 200
    assert completed.status_code == 403  # Its old enrollment marker no longer matches.
    assert TwoFactor.objects.get(user=user).enabled is False


def test_password_mutation_holds_account_lock_after_proof(user):
    changing = APIClient()
    changing.force_login(user)
    proof_complete = threading.Event()
    release = threading.Event()
    concurrent_password = make_password('ConcurrentResetPassword1!')

    def pause_before_mutation(*args, **kwargs):
        proof_complete.set()
        if not release.wait(10):
            raise AssertionError('test did not release password mutation')

    def concurrent_reset():
        with transaction.atomic():
            account = get_user_model().objects.select_for_update().get(pk=user.pk)
            account.password = concurrent_password
            account.save(update_fields=['password'])

    with ThreadPoolExecutor(max_workers=2) as executor:
        with patch('chat.views.validate_password', side_effect=pause_before_mutation):
            changing_call = executor.submit(_worker, lambda: changing.post(
                '/api/auth/password/', {
                    'current_password': PASSWORD, 'new_password': 'FirstReplacementPassword1!',
                }, format='json',
            ))
            try:
                assert proof_complete.wait(5)
                reset_call = executor.submit(_worker, concurrent_reset)
                blocked = _wait_for_lock_or_completion(reset_call)
            finally:
                release.set()
            changed = changing_call.result(timeout=10)
            reset_call.result(timeout=10)

    assert blocked, 'a reset overtook a password change after credential proof'
    assert changed.status_code == 200
    user.refresh_from_db()
    assert user.password == concurrent_password
