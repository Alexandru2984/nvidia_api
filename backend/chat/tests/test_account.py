"""Tests for change-password and delete-account."""
import uuid
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.utils import timezone
from rest_framework.test import APIClient

from chat.models import (
    Attachment,
    AuthenticatedSession,
    Conversation,
    ConversationGenerationLease,
    Message,
    TwoFactor,
)
from chat.twofactor import _hash_recovery


def _login(client, user):
    response = client.post(
        '/api/auth/login/',
        {'username': user.username, 'password': 'Hunter2pass'},
        format='json',
    )
    assert response.status_code == 200


@pytest.mark.django_db
class TestChangePassword:
    URL = '/api/auth/password/'

    def test_wrong_current_password_401(self, auth_client):
        r = auth_client.post(self.URL, {'current_password': 'nope', 'new_password': 'NewPass123!x'}, format='json')
        assert r.status_code == 401

    def test_weak_new_password_400(self, auth_client):
        r = auth_client.post(self.URL, {'current_password': 'Hunter2pass', 'new_password': 'short'}, format='json')
        assert r.status_code == 400

    def test_success_changes_password_and_keeps_session(self, user):
        client = APIClient()
        _login(client, user)
        r = client.post(self.URL, {'current_password': 'Hunter2pass', 'new_password': 'Brand-New-Pass-42'}, format='json')
        assert r.status_code == 200, r.content
        # session survives the change
        assert client.get('/api/models/').status_code == 200
        user.refresh_from_db()
        assert user.check_password('Brand-New-Pass-42')
        assert not user.check_password('Hunter2pass')

    def test_other_sessions_revoked(self, user):
        c1, c2 = APIClient(), APIClient()
        _login(c1, user)
        _login(c2, user)
        r = c1.post(self.URL, {'current_password': 'Hunter2pass', 'new_password': 'Brand-New-Pass-42'}, format='json')
        assert r.status_code == 200
        assert r.json()['sessions_revoked'] == 1
        assert c2.get('/api/models/').status_code in (401, 403)
        assert c1.get('/api/models/').status_code == 200

    def test_two_factor_account_requires_second_factor(self, auth_client, user):
        recovery = 'aaaa1111-bbbb2222'
        TwoFactor.objects.create(
            user=user,
            secret='irrelevant',
            enabled=True,
            recovery_codes=[_hash_recovery(recovery)],
        )

        missing = auth_client.post(self.URL, {
            'current_password': 'Hunter2pass',
            'new_password': 'Brand-New-Pass-42',
        }, format='json')
        accepted = auth_client.post(self.URL, {
            'current_password': 'Hunter2pass',
            'new_password': 'Brand-New-Pass-42',
            'code': recovery,
        }, format='json')

        assert missing.status_code == 401
        assert missing.json()['two_factor_required'] is True
        assert accepted.status_code == 200
        user.refresh_from_db()
        assert user.check_password('Brand-New-Pass-42')


@pytest.mark.django_db
class TestDeleteAccount:
    URL = '/api/auth/delete-account/'

    def test_wrong_password_401(self, auth_client, user):
        r = auth_client.post(self.URL, {'password': 'nope'}, format='json')
        assert r.status_code == 401
        assert get_user_model().objects.filter(pk=user.pk).exists()

    def test_success_deletes_user_and_data(self, auth_client, user, convo):
        Message.objects.create(conversation=convo, role='user', content='hi')
        r = auth_client.post(self.URL, {'password': 'Hunter2pass'}, format='json')
        assert r.status_code == 200
        assert r.json()['deleted'] is True
        assert not get_user_model().objects.filter(pk=user.pk).exists()
        assert not Conversation.objects.filter(pk=convo.pk).exists()
        assert Message.objects.count() == 0
        assert Attachment.objects.count() == 0
        # session is gone too
        assert auth_client.get('/api/models/').status_code in (401, 403)

    def test_success_revokes_every_django_session_before_user_cascade(self, user):
        first = APIClient()
        second = APIClient()
        _login(first, user)
        _login(second, user)
        session_keys = {first.session.session_key, second.session.session_key}
        assert Session.objects.filter(session_key__in=session_keys).count() == 2
        assert AuthenticatedSession.objects.filter(user=user).count() == 2

        response = first.post(self.URL, {'password': 'Hunter2pass'}, format='json')

        assert response.status_code == 200
        assert response.json() == {'deleted': True, 'sessions_revoked': 2}
        assert not Session.objects.filter(session_key__in=session_keys).exists()
        assert not AuthenticatedSession.objects.filter(session_id__in=session_keys).exists()
        assert not get_user_model().objects.filter(pk=user.pk).exists()
        assert second.get('/api/models/').status_code in (401, 403)

    def test_active_generation_blocks_irreversible_deletion(self, auth_client, user, convo):
        ConversationGenerationLease.objects.create(
            conversation=convo,
            token=uuid.uuid4(),
            expires_at=timezone.now() + timedelta(minutes=5),
        )

        response = auth_client.post(
            self.URL,
            {'password': 'Hunter2pass'},
            format='json',
        )

        assert response.status_code == 409
        assert response.json()['code'] == 'generation_in_progress'
        assert get_user_model().objects.filter(pk=user.pk).exists()

    def test_2fa_required_when_enabled(self, auth_client, user):
        TwoFactor.objects.create(user=user, secret='irrelevant', enabled=True,
                                 recovery_codes=[_hash_recovery('aaaa-bbbb')])
        r = auth_client.post(self.URL, {'password': 'Hunter2pass'}, format='json')
        assert r.status_code == 401
        assert r.json().get('two_factor_required') is True
        # recovery code satisfies the check
        r = auth_client.post(self.URL, {'password': 'Hunter2pass', 'code': 'aaaa-bbbb'}, format='json')
        assert r.status_code == 200
        assert not get_user_model().objects.filter(pk=user.pk).exists()

    def test_anonymous_401(self, client, db):
        r = client.post(self.URL, {'password': 'x'}, format='json')
        assert r.status_code in (401, 403)
