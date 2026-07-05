"""Tests for change-password and delete-account."""
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from chat.models import Attachment, Conversation, Message, TwoFactor
from chat.twofactor import _hash_recovery


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
        assert client.login(username='alice', password='Hunter2pass')
        r = client.post(self.URL, {'current_password': 'Hunter2pass', 'new_password': 'Brand-New-Pass-42'}, format='json')
        assert r.status_code == 200, r.content
        # session survives the change
        assert client.get('/api/models/').status_code == 200
        user.refresh_from_db()
        assert user.check_password('Brand-New-Pass-42')
        assert not user.check_password('Hunter2pass')

    def test_other_sessions_revoked(self, user):
        c1, c2 = APIClient(), APIClient()
        assert c1.login(username='alice', password='Hunter2pass')
        assert c2.login(username='alice', password='Hunter2pass')
        r = c1.post(self.URL, {'current_password': 'Hunter2pass', 'new_password': 'Brand-New-Pass-42'}, format='json')
        assert r.status_code == 200
        assert r.json()['sessions_revoked'] == 1
        assert c2.get('/api/models/').status_code in (401, 403)
        assert c1.get('/api/models/').status_code == 200


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
