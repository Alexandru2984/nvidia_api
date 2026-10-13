"""Durable object/storage boundaries for authenticated chat data."""
from unittest.mock import patch

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from chat.models import Conversation, ConversationGenerationLease, Message
from chat.models_catalog import DEFAULT_MODEL_ID


def _stream_ok(*args, **kwargs):
    yield ('chunk', 'bounded reply')
    yield ('usage', {'prompt_tokens': 2, 'completion_tokens': 2, 'total_tokens': 4})


def _stream_oversized(*args, **kwargs):
    yield ('chunk', 'x' * 65)
    yield ('usage', {'prompt_tokens': 2, 'completion_tokens': 20, 'total_tokens': 22})


def _consume(response):
    return b''.join(response.streaming_content).decode()


@pytest.mark.django_db
class TestChatObjectQuotas:
    def test_conversation_limit_is_owner_scoped_and_deletion_frees_capacity(
        self,
        auth_client,
        user,
        other_user,
        settings,
    ):
        settings.CHAT_MAX_CONVERSATIONS_PER_USER = 1
        existing = Conversation.objects.create(
            user=user,
            title='existing',
            model_id=DEFAULT_MODEL_ID,
        )
        Conversation.objects.create(
            user=other_user,
            title='not counted',
            model_id=DEFAULT_MODEL_ID,
        )

        rejected = auth_client.post('/api/conversations/', {}, format='json')

        assert rejected.status_code == 409
        assert rejected.json() == {
            'error': (
                'Your conversations limit has been reached. '
                'Delete older chat data and retry.'
            ),
            'code': 'conversations_limit',
            'used': 1,
            'limit': 1,
        }
        existing.delete()
        accepted = auth_client.post('/api/conversations/', {}, format='json')
        assert accepted.status_code == 201

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_cross_conversation_message_reservations_enforce_user_limit(
        self,
        mock_stream,
        auth_client,
        convo,
        user,
        settings,
    ):
        settings.CHAT_MAX_MESSAGES_PER_USER = 2
        settings.CHAT_MAX_MESSAGES_PER_CONVERSATION = 2
        other = Conversation.objects.create(
            user=user,
            title='other',
            model_id=DEFAULT_MODEL_ID,
        )
        first = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'first'},
            format='json',
        )

        rejected = auth_client.post(
            f'/api/conversations/{other.id}/messages/',
            {'content': 'second'},
            format='json',
        )

        assert first.status_code == 200
        assert rejected.status_code == 409
        assert rejected.json()['code'] == 'messages_limit'
        assert rejected.json()['used'] == 2
        assert user.daily_ai_usage.get().chat_requests == 1
        mock_stream.assert_not_called()
        first.close()

        retry = auth_client.post(
            f'/api/conversations/{other.id}/messages/',
            {'content': 'now accepted'},
            format='json',
        )
        assert retry.status_code == 200
        retry.close()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_per_conversation_limit_blocks_before_budget_or_provider(
        self,
        mock_stream,
        auth_client,
        convo,
        user,
        settings,
    ):
        settings.CHAT_MAX_MESSAGES_PER_CONVERSATION = 2
        Message.objects.create(conversation=convo, role='user', content='old')

        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'would exceed'},
            format='json',
        )

        assert response.status_code == 409
        assert response.json()['code'] == 'conversation_messages_limit'
        assert response.json()['used'] == 1
        assert not ConversationGenerationLease.objects.exists()
        assert not user.daily_ai_usage.exists()
        mock_stream.assert_not_called()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_message_slots_transition_from_reserved_to_persisted(
        self,
        mock_stream,
        auth_client,
        convo,
    ):
        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'hello'},
            format='json',
        )
        lease = ConversationGenerationLease.objects.get(conversation=convo)
        assert lease.reserved_messages == 1
        assert convo.messages.count() == 1

        stream = iter(response.streaming_content)
        next(stream)  # user message
        next(stream)  # provider chunk
        done = next(stream).decode()

        lease.refresh_from_db()
        assert lease.reserved_messages == 0
        assert '"done": true' in done
        assert convo.messages.count() == 2
        response.close()
        assert not ConversationGenerationLease.objects.exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_oversized)
    def test_oversized_assistant_response_is_not_persisted(
        self,
        mock_stream,
        auth_client,
        convo,
        settings,
    ):
        settings.CHAT_MAX_ASSISTANT_CHARS = 64

        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'bounded'},
            format='json',
        )
        body = _consume(response)

        assert 'configured output limit' in body
        assert not convo.messages.exists()
        assert not ConversationGenerationLease.objects.exists()

    @patch('chat.views._stream_nvidia', side_effect=_stream_oversized)
    def test_oversized_regeneration_preserves_existing_branch(
        self,
        mock_stream,
        auth_client,
        convo,
        settings,
    ):
        settings.CHAT_MAX_ASSISTANT_CHARS = 64
        Message.objects.create(conversation=convo, role='user', content='question')
        old = Message.objects.create(
            conversation=convo,
            role='assistant',
            content='old answer',
        )

        response = auth_client.post(f'/api/messages/{old.id}/regenerate/')
        body = _consume(response)

        assert 'configured output limit' in body
        assert Message.objects.filter(pk=old.pk, content='old answer').exists()
        assert convo.messages.count() == 2

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_trailing_user_regeneration_respects_message_limit(
        self,
        mock_stream,
        auth_client,
        convo,
        settings,
    ):
        settings.CHAT_MAX_MESSAGES_PER_USER = 3
        settings.CHAT_MAX_MESSAGES_PER_CONVERSATION = 2
        Message.objects.create(
            conversation=convo,
            role='assistant',
            content='earlier answer',
        )
        user_message = Message.objects.create(
            conversation=convo,
            role='user',
            content='question',
        )

        response = auth_client.post(f'/api/messages/{user_message.id}/regenerate/')

        assert response.status_code == 409
        assert response.json()['code'] == 'conversation_messages_limit'
        assert convo.messages.count() == 2
        assert not ConversationGenerationLease.objects.exists()
        mock_stream.assert_not_called()

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_assistant_regeneration_can_replace_at_message_limit(
        self,
        mock_stream,
        auth_client,
        convo,
        settings,
    ):
        settings.CHAT_MAX_MESSAGES_PER_USER = 2
        settings.CHAT_MAX_MESSAGES_PER_CONVERSATION = 2
        Message.objects.create(conversation=convo, role='user', content='question')
        old = Message.objects.create(
            conversation=convo,
            role='assistant',
            content='old answer',
        )

        response = auth_client.post(f'/api/messages/{old.id}/regenerate/')
        body = _consume(response)

        assert '"done": true' in body
        assert convo.messages.count() == 2
        assert not Message.objects.filter(pk=old.pk).exists()
        assert not ConversationGenerationLease.objects.exists()

    def test_account_usage_publishes_object_limits(self, auth_client, convo, settings):
        Message.objects.create(conversation=convo, role='user', content='one')

        body = auth_client.get('/api/account/usage/').json()

        assert body['conversations'] == 1
        assert body['conversation_limit'] == settings.CHAT_MAX_CONVERSATIONS_PER_USER
        assert body['messages'] == 1
        assert body['message_limit'] == settings.CHAT_MAX_MESSAGES_PER_USER
        assert (
            body['message_limit_per_conversation']
            == settings.CHAT_MAX_MESSAGES_PER_CONVERSATION
        )

    def test_database_rejects_invalid_message_reservation(self, convo):
        lease = ConversationGenerationLease.objects.create(
            conversation=convo,
            token='00000000-0000-4000-8000-000000000001',
            expires_at=timezone.now(),
        )

        with pytest.raises(IntegrityError), transaction.atomic():
            ConversationGenerationLease.objects.filter(pk=lease.pk).update(
                reserved_messages=3,
            )
