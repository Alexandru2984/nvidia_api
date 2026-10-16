"""Cross-worker generation exclusion and stream lifecycle guarantees."""
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
from chat.views import _renew_generation_lease


def _stream_ok(*args, **kwargs):
    yield ('chunk', 'safe reply')
    yield ('usage', {'prompt_tokens': 2, 'completion_tokens': 2, 'total_tokens': 4})


def _stream_error(*args, **kwargs):
    yield ('error', 'provider unavailable')


def _consume(response):
    return b''.join(response.streaming_content).decode()


@pytest.mark.django_db
class TestConversationGenerationLease:
    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_second_send_is_rejected_until_first_response_closes(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        first = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'first'},
            format='json',
        )

        second = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'second'},
            format='json',
        )

        assert first.status_code == 200
        assert second.status_code == 409
        assert second.json()['code'] == 'generation_in_progress'
        assert int(second['Retry-After']) >= 1
        mock_stream.assert_not_called()
        first.close()
        assert not ConversationGenerationLease.objects.filter(
            conversation=convo,
        ).exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_close_before_iteration_rolls_back_and_releases_reservation(
        self,
        mock_stream,
        auth_client,
        convo,
        user,
        settings,
    ):
        settings.AI_CHAT_TOKEN_RESERVATION = 100
        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'never consumed'},
            format='json',
        )

        assert convo.messages.count() == 1
        response.close()

        assert convo.messages.count() == 0
        assert not ConversationGenerationLease.objects.exists()
        usage = user.daily_ai_usage.get(day=timezone.localdate())
        assert usage.reserved_tokens == 0
        assert usage.prompt_tokens == 0
        assert usage.completion_tokens == 0
        mock_stream.assert_not_called()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_next_send_succeeds_after_unstarted_response_closes(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        first = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'abandoned'},
            format='json',
        )
        first.close()

        second = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'real'},
            format='json',
        )
        body = _consume(second)

        assert 'safe reply' in body
        assert convo.messages.count() == 2
        assert not ConversationGenerationLease.objects.exists()
        assert mock_stream.call_count == 1

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_different_conversations_can_generate_independently(
        self,
        mock_stream,
        auth_client,
        convo,
        user,
    ):
        other = Conversation.objects.create(
            user=user,
            title='Other',
            model_id=DEFAULT_MODEL_ID,
        )

        first = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'one'},
            format='json',
        )
        second = auth_client.post(
            f'/api/conversations/{other.id}/messages/',
            {'content': 'two'},
            format='json',
        )

        assert first.status_code == second.status_code == 200
        assert ConversationGenerationLease.objects.count() == 2
        first.close()
        second.close()
        assert ConversationGenerationLease.objects.count() == 0
        mock_stream.assert_not_called()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_expired_lease_is_reclaimed(self, mock_stream, auth_client, convo):
        old_token = uuid.uuid4()
        ConversationGenerationLease.objects.create(
            conversation=convo,
            token=old_token,
            expires_at=timezone.now() - timedelta(seconds=1),
        )

        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'reclaim'},
            format='json',
        )

        assert response.status_code == 200
        lease = ConversationGenerationLease.objects.get(conversation=convo)
        assert lease.token != old_token
        response.close()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_expired_lease_cannot_renew_or_commit_send(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'must stay fenced'},
            format='json',
        )
        stream = iter(response.streaming_content)
        next(stream)  # persisted user message
        next(stream)  # provider chunk
        lease = ConversationGenerationLease.objects.get(conversation=convo)
        ConversationGenerationLease.objects.filter(pk=lease.pk).update(
            expires_at=timezone.now() - timedelta(seconds=1),
        )

        assert _renew_generation_lease(
            convo.pk,
            lease.token,
            lease.generation_request_id,
        ) == 0
        with pytest.raises(RuntimeError, match='expired or was lost'):
            next(stream)

        assert not convo.messages.exists()
        assert not ConversationGenerationLease.objects.exists()
        assert GenerationRequest.objects.get().state == GenerationRequest.STATE_FAILED

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_expired_zero_reservation_regeneration_cannot_replace_branch(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        Message.objects.create(conversation=convo, role='user', content='question')
        old_reply = Message.objects.create(
            conversation=convo,
            role='assistant',
            content='keep this branch',
        )
        response = auth_client.post(f'/api/messages/{old_reply.id}/regenerate/')
        stream = iter(response.streaming_content)
        next(stream)  # provider chunk
        ConversationGenerationLease.objects.filter(conversation=convo).update(
            expires_at=timezone.now() - timedelta(seconds=1),
        )

        with pytest.raises(RuntimeError, match='expired or was lost'):
            next(stream)

        assert Message.objects.filter(pk=old_reply.pk, content='keep this branch').exists()
        assert convo.messages.count() == 2
        assert not ConversationGenerationLease.objects.exists()
        assert GenerationRequest.objects.get().state == GenerationRequest.STATE_FAILED

    @patch('chat.views._reserve_provider_call', side_effect=RuntimeError('database failure'))
    def test_budget_reservation_exception_releases_lease(
        self,
        reserve,
        auth_client,
        convo,
    ):
        with pytest.raises(RuntimeError, match='database failure'):
            auth_client.post(
                f'/api/conversations/{convo.id}/messages/',
                {'content': 'fails during setup'},
                format='json',
            )

        assert not ConversationGenerationLease.objects.exists()
        assert not convo.messages.exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_regenerate_conflict_preserves_existing_branch(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        Message.objects.create(conversation=convo, role='user', content='old question')
        old_reply = Message.objects.create(
            conversation=convo,
            role='assistant',
            content='old reply',
        )
        active_send = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'new question'},
            format='json',
        )
        ids_before = list(convo.messages.values_list('id', flat=True))

        response = auth_client.post(f'/api/messages/{old_reply.id}/regenerate/')

        assert response.status_code == 409
        assert response.json()['code'] == 'generation_in_progress'
        assert list(convo.messages.values_list('id', flat=True)) == ids_before
        active_send.close()
        assert Message.objects.filter(pk=old_reply.pk, content='old reply').exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_conversation_mutation_is_blocked_during_generation(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        active_send = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'active'},
            format='json',
        )

        response = auth_client.patch(
            f'/api/conversations/{convo.id}/',
            {'title': 'racing title'},
            format='json',
        )

        assert response.status_code == 409
        assert response.json()['code'] == 'generation_in_progress'
        active_send.close()
        convo.refresh_from_db()
        assert convo.title == 'Test convo'

    @patch('chat.views._stream_nvidia', side_effect=_stream_error)
    def test_failed_regeneration_keeps_old_reply(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        Message.objects.create(conversation=convo, role='user', content='question')
        old_reply = Message.objects.create(
            conversation=convo,
            role='assistant',
            content='keep me',
        )

        response = auth_client.post(f'/api/messages/{old_reply.id}/regenerate/')
        body = _consume(response)

        assert 'error' in body
        assert Message.objects.filter(pk=old_reply.pk, content='keep me').exists()
        assert not ConversationGenerationLease.objects.exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_unstarted_regeneration_keeps_old_reply_and_releases_budget(
        self,
        mock_stream,
        auth_client,
        convo,
        user,
    ):
        Message.objects.create(conversation=convo, role='user', content='question')
        old_reply = Message.objects.create(
            conversation=convo,
            role='assistant',
            content='still here',
        )
        response = auth_client.post(f'/api/messages/{old_reply.id}/regenerate/')

        response.close()

        assert Message.objects.filter(pk=old_reply.pk, content='still here').exists()
        assert not ConversationGenerationLease.objects.exists()
        assert user.daily_ai_usage.get(day=timezone.localdate()).reserved_tokens == 0
        mock_stream.assert_not_called()

    @patch('chat.views._resolve_attachments')
    def test_attachment_is_revalidated_under_row_lock(
        self,
        resolve,
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
        resolve.side_effect = [[attachment], None]

        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'read', 'attachment_ids': [attachment.pk]},
            format='json',
        )

        assert response.status_code == 409
        assert response.json()['code'] == 'attachment_already_claimed'
        assert not convo.messages.exists()
        assert not ConversationGenerationLease.objects.exists()
        assert user.daily_ai_usage.get(day=timezone.localdate()).reserved_tokens == 0
        assert resolve.call_args_list[-1].kwargs == {'for_update': True}
