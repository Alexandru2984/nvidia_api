"""Durable generation idempotency, replay, and crash fencing."""
import json
import uuid
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from chat.models import (
    Attachment,
    Conversation,
    ConversationGenerationLease,
    GenerationRequest,
    Message,
)
from chat.models_catalog import DEFAULT_MODEL_ID


def _stream_ok(*args, **kwargs):
    yield ('chunk', 'durable reply')
    yield ('usage', {'prompt_tokens': 2, 'completion_tokens': 2, 'total_tokens': 4})


def _stream_error(*args, **kwargs):
    yield ('error', 'provider unavailable')


def _consume(response):
    return b''.join(response.streaming_content).decode()


def _events(body):
    return [
        json.loads(block.removeprefix('data:').strip())
        for block in body.split('\n\n')
        if block.startswith('data:')
    ]


@pytest.mark.django_db
class TestGenerationIdempotency:
    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_completed_send_replays_without_second_provider_call(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'only once'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        first_body = _consume(first)

        second = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'only once'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        second_events = _events(_consume(second))

        assert first.status_code == second.status_code == 200
        assert first['Idempotency-Key'] == second['Idempotency-Key'] == request_id
        assert 'durable reply' in first_body
        assert second_events[-1]['done'] is True
        assert second_events[-1]['replayed'] is True
        assert second_events[-1]['generation_state'] == GenerationRequest.STATE_COMPLETED
        assert mock_stream.call_count == 1
        assert convo.messages.count() == 2
        request = GenerationRequest.objects.get()
        assert request.user_message.role == 'user'
        assert request.assistant_message.role == 'assistant'
        assert request.state == GenerationRequest.STATE_COMPLETED

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_completed_send_with_claimed_attachment_is_still_replayable(
        self,
        mock_stream,
        auth_client,
        convo,
        user,
    ):
        attachment = Attachment.objects.create(
            user=user,
            file=SimpleUploadedFile('note.txt', b'note', content_type='text/plain'),
            original_name='note.txt',
            mime_type='text/plain',
            size=4,
            kind=Attachment.KIND_DOCUMENT,
            extracted_text='note',
        )
        request_id = str(uuid.uuid4())
        payload = {'content': 'read it', 'attachment_ids': [attachment.pk]}
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            payload,
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        _consume(first)
        attachment.refresh_from_db()
        assert attachment.message_id is not None

        replay = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            payload,
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        assert replay.status_code == 200
        assert _events(_consume(replay))[-1]['replayed'] is True
        assert mock_stream.call_count == 1

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_same_key_with_different_payload_fails_closed(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'first payload'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        _consume(first)

        conflict = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'changed payload'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        assert conflict.status_code == 409
        assert conflict.json()['code'] == 'idempotency_key_conflict'
        assert mock_stream.call_count == 1
        assert GenerationRequest.objects.count() == 1

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_duplicate_while_active_returns_request_specific_conflict(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'in flight'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        duplicate = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'in flight'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        assert duplicate.status_code == 409
        assert duplicate.json()['code'] == 'generation_request_in_progress'
        assert int(duplicate['Retry-After']) >= 1
        assert GenerationRequest.objects.count() == 1
        assert mock_stream.call_count == 0
        first.close()

    @patch('chat.views._stream_nvidia', side_effect=_stream_error)
    def test_failed_request_is_not_automatically_executed_again(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'fail once'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        assert 'provider unavailable' in _consume(first)

        retry = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'fail once'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        assert retry.status_code == 409
        assert retry.json() == {
            'error': 'This generation request is closed and cannot be executed again.',
            'code': 'generation_request_closed',
            'generation_state': GenerationRequest.STATE_FAILED,
        }
        assert mock_stream.call_count == 1
        assert not convo.messages.exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_expired_request_is_interrupted_and_pending_message_is_reconciled(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'worker disappears'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        ConversationGenerationLease.objects.filter(conversation=convo).update(
            expires_at=timezone.now() - timedelta(seconds=1),
        )

        retry = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'worker disappears'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        assert retry.status_code == 409
        assert retry.json()['generation_state'] == GenerationRequest.STATE_INTERRUPTED
        assert not convo.messages.exists()
        assert GenerationRequest.objects.get().outcome_code == 'lease_missing_or_expired'
        assert mock_stream.call_count == 0
        first.close()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_partial_disconnect_is_replayable_without_provider_retry(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'keep partial'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        iterator = iter(first.streaming_content)
        next(iterator)
        next(iterator)
        first.close()

        generation_request = GenerationRequest.objects.get()
        assert generation_request.state == GenerationRequest.STATE_CANCELED
        assert generation_request.outcome_code == 'client_disconnected_partial'
        assert generation_request.assistant_message.content == 'durable reply'

        replay = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'keep partial'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        event = _events(_consume(replay))[-1]

        assert event['replayed'] is True
        assert event['generation_state'] == GenerationRequest.STATE_CANCELED
        assert event['assistant_message']['content'] == 'durable reply'
        assert mock_stream.call_count == 1

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_regeneration_replays_after_original_target_was_deleted(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        Message.objects.create(conversation=convo, role='user', content='question')
        old_reply = Message.objects.create(conversation=convo, role='assistant', content='old')
        request_id = str(uuid.uuid4())

        first = auth_client.post(
            f'/api/messages/{old_reply.pk}/regenerate/',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        _consume(first)
        assert not Message.objects.filter(pk=old_reply.pk).exists()

        replay = auth_client.post(
            f'/api/messages/{old_reply.pk}/regenerate/',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        event = _events(_consume(replay))[-1]

        assert replay.status_code == 200
        assert event['replayed'] is True
        assert event['assistant_message']['content'] == 'durable reply'
        assert mock_stream.call_count == 1

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_key_scope_is_per_user(
        self,
        mock_stream,
        auth_client,
        other_client,
        convo,
        other_user,
    ):
        other_convo = Conversation.objects.create(
            user=other_user,
            title='Other',
            model_id=DEFAULT_MODEL_ID,
        )
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'same key'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        second = other_client.post(
            f'/api/conversations/{other_convo.pk}/messages/',
            {'content': 'same key'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        _consume(first)
        _consume(second)
        assert GenerationRequest.objects.count() == 2
        assert mock_stream.call_count == 2

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_secret_key_fallback_preserves_request_fingerprint_replay(
        self,
        mock_stream,
        auth_client,
        convo,
        settings,
    ):
        old_secret = settings.SECRET_KEY
        request_id = str(uuid.uuid4())
        first = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'survive key rotation'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )
        _consume(first)

        settings.SECRET_KEY = 'rotated-test-secret-key'
        settings.SECRET_KEY_FALLBACKS = [old_secret]
        replay = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'survive key rotation'},
            format='json',
            HTTP_IDEMPOTENCY_KEY=request_id,
        )

        assert replay.status_code == 200
        assert _events(_consume(replay))[-1]['replayed'] is True
        assert mock_stream.call_count == 1

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_invalid_key_is_rejected_before_state_or_provider_work(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        response = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'invalid key'},
            format='json',
            HTTP_IDEMPOTENCY_KEY='not-a-uuid',
        )

        assert response.status_code == 400
        assert response.json()['code'] == 'invalid_idempotency_key'
        assert not GenerationRequest.objects.exists()
        assert not ConversationGenerationLease.objects.exists()
        mock_stream.assert_not_called()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_legacy_client_without_key_gets_server_generated_key(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        response = auth_client.post(
            f'/api/conversations/{convo.pk}/messages/',
            {'content': 'legacy client'},
            format='json',
        )
        response_key = response['Idempotency-Key']
        uuid.UUID(response_key)
        _consume(response)

        assert str(GenerationRequest.objects.get().idempotency_key) == response_key
        assert mock_stream.call_count == 1
