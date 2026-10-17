"""Owner-only, strongly authenticated and bounded account portability export."""
import json
import uuid
from datetime import timedelta

import pytest
from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from chat.models import (
    Attachment,
    AuthenticatedSession,
    ChatHistoryRetention,
    Conversation,
    DailyAIUsage,
    GenerationRequest,
    Message,
    TwoFactor,
)
from chat.models_catalog import DEFAULT_MODEL_ID


def _reauthenticate(client):
    response = client.post(
        '/api/auth/reauthenticate/',
        {'password': 'Hunter2pass'},
        format='json',
    )
    assert response.status_code == 200


def _body(response):
    return b''.join(response.streaming_content)


@pytest.mark.django_db
class TestAccountExport:
    def test_requires_authentication_and_recent_strong_auth(self, client, auth_client):
        assert client.get('/api/account/export/').status_code in (401, 403)

        stale = auth_client.get('/api/account/export/')

        assert stale.status_code == 403
        assert stale.json()['reauthentication_required'] is True

    def test_streams_only_owner_data_and_omits_secrets_and_file_bodies(
        self,
        auth_client,
        user,
        other_user,
    ):
        ChatHistoryRetention.objects.create(user=user, archived_days=90)
        conversation = Conversation.objects.create(
            user=user,
            title='Private export',
            model_id=DEFAULT_MODEL_ID,
            system_prompt='owner system prompt',
        )
        message = Message.objects.create(
            conversation=conversation,
            role='user',
            content='owner private message',
        )
        attachment = Attachment.objects.create(
            user=user,
            message=message,
            file=SimpleUploadedFile('owner.txt', b'file body', content_type='text/plain'),
            original_name='owner.txt',
            mime_type='text/plain',
            size=9,
            kind=Attachment.KIND_DOCUMENT,
            extracted_text='never export extracted text',
            content_sha256='a' * 64,
        )
        TwoFactor.objects.create(
            user=user,
            secret='encrypted-two-factor-secret',
            recovery_codes=['hashed-recovery-code'],
        )
        GenerationRequest.objects.create(
            user=user,
            conversation=conversation,
            idempotency_key=uuid.uuid4(),
            operation=GenerationRequest.OPERATION_SEND,
            request_fingerprint='request-fingerprint-secret',
            state=GenerationRequest.STATE_COMPLETED,
            completed_at=timezone.now(),
        )
        DailyAIUsage.objects.create(
            user=user,
            day=timezone.localdate() - timedelta(days=1),
            chat_requests=2,
            prompt_tokens=12,
        )
        other_conversation = Conversation.objects.create(
            user=other_user,
            title='Other owner secret',
            model_id=DEFAULT_MODEL_ID,
        )
        Message.objects.create(
            conversation=other_conversation,
            role='user',
            content='other owner message',
        )
        _reauthenticate(auth_client)
        session = AuthenticatedSession.objects.get(user=user)

        response = auth_client.get('/api/account/export/')
        payload = json.loads(_body(response))

        assert response.status_code == 200
        assert response.streaming is True
        assert response['Content-Type'].startswith('application/json')
        assert 'attachment;' in response['Content-Disposition']
        assert response['Content-Disposition'].endswith('.json"')
        assert 'private' in response['Cache-Control']
        assert 'no-store' in response['Cache-Control']
        assert payload['schema_version'] == 1
        assert payload['account']['username'] == user.username
        assert payload['preferences_and_security']['archived_chat_retention_days'] == 90
        assert payload['attachment_files_included'] is False
        assert payload['counts']['conversations'] == 1
        assert payload['counts']['messages'] == 1
        assert payload['counts']['attachments'] == 1
        assert payload['conversations'][0]['system_prompt'] == 'owner system prompt'
        assert payload['messages'][0]['content'] == 'owner private message'
        assert payload['attachments'][0]['original_name'] == 'owner.txt'
        assert payload['attachments'][0]['file_bytes_included'] is False
        assert payload['ai_usage_history'][0]['prompt_tokens'] == 12
        serialized = json.dumps(payload)
        assert 'Other owner secret' not in serialized
        assert 'other owner message' not in serialized
        assert 'file body' not in serialized
        assert 'never export extracted text' not in serialized
        assert attachment.file.name not in serialized
        assert 'encrypted-two-factor-secret' not in serialized
        assert 'hashed-recovery-code' not in serialized
        assert 'request-fingerprint-secret' not in serialized
        assert session.session_id not in serialized
        assert session.handle not in serialized
        assert 'Hunter2pass' not in serialized
        assert 'content_sha256' not in serialized
        assert 'password' not in serialized
        assert 'session_key' not in serialized
        assert 'handle' not in serialized

    def test_rejects_oversized_or_overpopulated_export_before_streaming(
        self,
        auth_client,
        user,
        settings,
    ):
        conversation = Conversation.objects.create(
            user=user,
            title='Large',
            model_id=DEFAULT_MODEL_ID,
        )
        Message.objects.create(
            conversation=conversation,
            role='user',
            content='bounded content',
        )
        _reauthenticate(auth_client)
        settings.ACCOUNT_EXPORT_MAX_BYTES = 1

        too_large = auth_client.get('/api/account/export/')

        assert too_large.status_code == 413
        assert too_large.json()['code'] == 'account_export_too_large'

        settings.ACCOUNT_EXPORT_MAX_BYTES = 128 * 1024 * 1024
        settings.ACCOUNT_EXPORT_MAX_RECORDS = 1
        too_many = auth_client.get('/api/account/export/')
        assert too_many.status_code == 413
        assert too_many.json()['record_limit'] == 1

    def test_limits_account_exports_to_two_per_day(self, auth_client, settings):
        settings.RATELIMIT_ENABLE = True
        cache.clear()
        _reauthenticate(auth_client)

        first = auth_client.get('/api/account/export/')
        second = auth_client.get('/api/account/export/')
        assert first.status_code == 200
        assert second.status_code == 200
        _body(first)
        _body(second)

        limited = auth_client.get('/api/account/export/')

        assert limited.status_code == 429
        assert limited.json() == {'error': 'Too many requests. Slow down and try again.'}
