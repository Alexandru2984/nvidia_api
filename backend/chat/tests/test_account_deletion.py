"""Cancelable scheduled account deletion API coverage."""
from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from chat.models import AccountDeletionRequest, TwoFactor
from chat.twofactor import _hash_recovery


@pytest.mark.django_db
class TestAccountDeletionSchedule:
    URL = '/api/account/deletion/'

    def test_schedule_is_strongly_authenticated_idempotent_and_cancelable(
        self,
        auth_client,
        user,
        settings,
        caplog,
    ):
        caplog.set_level('WARNING', logger='security')
        settings.ACCOUNT_DELETION_GRACE_DAYS = 3

        initial = auth_client.get(self.URL)
        wrong = auth_client.post(self.URL, {'password': 'wrong'}, format='json')
        scheduled = auth_client.post(
            self.URL,
            {'password': 'Hunter2pass'},
            format='json',
        )

        assert initial.status_code == 200
        assert initial.json()['scheduled'] is False
        assert wrong.status_code == 401
        assert scheduled.status_code == 201
        payload = scheduled.json()
        assert payload['scheduled'] is True
        assert payload['grace_days'] == 3
        execute_after = parse_datetime(payload['execute_after'])
        assert execute_after is not None
        assert timedelta(days=2, hours=23) < execute_after - timezone.now() <= timedelta(days=3)

        repeated = auth_client.post(
            self.URL,
            {'password': 'Hunter2pass'},
            format='json',
        )
        assert repeated.status_code == 200
        assert repeated.json()['execute_after'] == payload['execute_after']
        assert AccountDeletionRequest.objects.filter(user=user).count() == 1

        failed_cancel = auth_client.delete(
            self.URL,
            {'password': 'wrong'},
            format='json',
        )
        canceled = auth_client.delete(
            self.URL,
            {'password': 'Hunter2pass'},
            format='json',
        )
        assert failed_cancel.status_code == 401
        assert canceled.status_code == 200
        assert canceled.json()['scheduled'] is False
        assert not AccountDeletionRequest.objects.filter(user=user).exists()
        messages = '\n'.join(record.getMessage() for record in caplog.records)
        assert messages.count('event=account_deletion_scheduled') == 1
        assert messages.count('event=account_deletion_canceled') == 1

    def test_due_deletion_can_no_longer_be_canceled(self, auth_client, user):
        deletion = AccountDeletionRequest.objects.create(
            user=user,
            execute_after=timezone.now() + timedelta(days=1),
        )
        AccountDeletionRequest.objects.filter(pk=deletion.pk).update(
            requested_at=timezone.now() - timedelta(days=2),
            execute_after=timezone.now() - timedelta(days=1),
        )

        response = auth_client.delete(
            self.URL,
            {'password': 'Hunter2pass'},
            format='json',
        )

        assert response.status_code == 409
        assert response.json()['code'] == 'deletion_due'
        assert response.json()['scheduled'] is True
        assert AccountDeletionRequest.objects.filter(user=user).exists()

    def test_schedule_requires_second_factor_when_enabled(self, auth_client, user):
        recovery = 'aaaa1111-bbbb2222'
        TwoFactor.objects.create(
            user=user,
            secret='irrelevant',
            enabled=True,
            recovery_codes=[_hash_recovery(recovery)],
        )

        missing = auth_client.post(
            self.URL,
            {'password': 'Hunter2pass'},
            format='json',
        )
        accepted = auth_client.post(
            self.URL,
            {'password': 'Hunter2pass', 'code': recovery},
            format='json',
        )

        assert missing.status_code == 401
        assert missing.json()['two_factor_required'] is True
        assert accepted.status_code == 201

    def test_anonymous_status_is_private(self, client):
        assert client.get(self.URL).status_code in (401, 403)

    def test_status_is_owner_scoped(self, auth_client, user, other_user):
        AccountDeletionRequest.objects.create(
            user=other_user,
            execute_after=timezone.now() + timedelta(days=7),
        )

        response = auth_client.get(self.URL)

        assert response.status_code == 200
        assert response.json()['scheduled'] is False
        assert not AccountDeletionRequest.objects.filter(user=user).exists()

    def test_database_rejects_deadline_before_request_time(self, user):
        deletion = AccountDeletionRequest.objects.create(
            user=user,
            execute_after=timezone.now() + timedelta(days=7),
        )

        with pytest.raises(IntegrityError), transaction.atomic():
            AccountDeletionRequest.objects.filter(pk=deletion.pk).update(
                execute_after=deletion.requested_at - timedelta(seconds=1),
            )
