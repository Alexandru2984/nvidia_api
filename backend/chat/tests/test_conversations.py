"""Tests for conversation CRUD, send_message streaming, ownership."""
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from chat.models import Attachment, Conversation, Message
from chat.models_catalog import DEFAULT_MODEL_ID, MODEL_IDS, VISION_MODEL_IDS


def _consume_sse(response):
    """Drain a StreamingHttpResponse and return the decoded body."""
    return b''.join(response.streaming_content).decode()


@pytest.mark.django_db
class TestConversationsList:
    def test_lists_only_own(self, auth_client, other_client, user, other_user):
        Conversation.objects.create(user=user, title='mine', model_id=DEFAULT_MODEL_ID)
        Conversation.objects.create(user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID)
        r = auth_client.get('/api/conversations/')
        assert r.status_code == 200
        titles = [c['title'] for c in r.json()]
        assert titles == ['mine']


@pytest.mark.django_db
class TestConversationCreate:
    def test_create_with_default_model(self, auth_client):
        r = auth_client.post('/api/conversations/', {}, format='json')
        assert r.status_code == 201
        assert r.json()['model_id'] == DEFAULT_MODEL_ID

    def test_create_with_explicit_model(self, auth_client):
        m = next(iter(VISION_MODEL_IDS & MODEL_IDS))
        r = auth_client.post('/api/conversations/', {'model_id': m}, format='json')
        assert r.status_code == 201
        assert r.json()['model_id'] == m

    def test_create_rejects_unknown_model(self, auth_client):
        r = auth_client.post('/api/conversations/', {'model_id': 'fake/model'}, format='json')
        assert r.status_code == 400

    def test_create_truncates_long_title(self, auth_client):
        r = auth_client.post('/api/conversations/', {'title': 'x' * 500}, format='json')
        assert r.status_code == 201
        assert len(r.json()['title']) <= 200


@pytest.mark.django_db
class TestConversationDetail:
    def test_get_own_convo(self, auth_client, convo):
        r = auth_client.get(f'/api/conversations/{convo.id}/')
        assert r.status_code == 200
        assert r.json()['id'] == convo.id

    def test_get_other_users_convo_returns_404(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID)
        r = auth_client.get(f'/api/conversations/{c.id}/')
        assert r.status_code == 404

    def test_patch_title(self, auth_client, convo):
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {'title': 'renamed'}, format='json')
        assert r.status_code == 200
        convo.refresh_from_db()
        assert convo.title == 'renamed'

    def test_patch_model_id_persists(self, auth_client, convo):
        m = next(iter(VISION_MODEL_IDS & MODEL_IDS))
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {'model_id': m}, format='json')
        assert r.status_code == 200
        convo.refresh_from_db()
        assert convo.model_id == m

    def test_patch_unknown_model_rejected(self, auth_client, convo):
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {'model_id': 'fake/model'}, format='json')
        assert r.status_code == 400

    def test_delete(self, auth_client, convo):
        r = auth_client.delete(f'/api/conversations/{convo.id}/')
        assert r.status_code == 204
        assert not Conversation.objects.filter(pk=convo.id).exists()

    def test_cannot_delete_other_users(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID)
        r = auth_client.delete(f'/api/conversations/{c.id}/')
        assert r.status_code == 404


def _stream_ok(*args, **kwargs):
    yield ('chunk', 'Hello')
    yield ('chunk', ' world')
    yield ('usage', {'total_tokens': 10})


def _stream_error(*args, **kwargs):
    yield ('error', 'NVIDIA exploded')


def _stream_empty(*args, **kwargs):
    return
    yield  # pragma: no cover  (make this a generator)


@pytest.mark.django_db
class TestSendMessage:
    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_happy_path_creates_user_and_assistant_messages(self, mock_stream, auth_client, convo):
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'hi'}, format='json')
        assert r.status_code == 200
        body = _consume_sse(r)
        assert 'Hello' in body
        assert 'world' in body
        assert convo.messages.count() == 2
        assert convo.messages.get(role='assistant').content == 'Hello world'

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_first_message_sets_title(self, mock_stream, auth_client, convo):
        # New convo title is 'Test convo' (set in fixture). Reset to 'New Chat' so the rename triggers.
        convo.title = 'New Chat'
        convo.save()
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'How big is the moon?'}, format='json')
        _consume_sse(r)
        convo.refresh_from_db()
        assert convo.title == 'How big is the moon?'

    @patch('chat.views._stream_nvidia', side_effect=_stream_error)
    def test_api_error_rolls_back_user_message(self, mock_stream, auth_client, convo):
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'hi'}, format='json')
        _consume_sse(r)
        # Both user and (never-created) assistant message should be absent.
        assert convo.messages.count() == 0

    @patch('chat.views._stream_nvidia', side_effect=_stream_empty)
    def test_empty_response_rolls_back(self, mock_stream, auth_client, convo):
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'hi'}, format='json')
        _consume_sse(r)
        assert convo.messages.count() == 0

    def test_empty_content_no_attachments_400(self, auth_client, convo):
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': ''}, format='json')
        assert r.status_code == 400

    def test_message_too_long_400(self, auth_client, convo, settings):
        settings.CHAT_MAX_MESSAGE_CHARS = 50
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'x' * 100}, format='json')
        assert r.status_code == 400

    def test_too_many_attachments_400(self, auth_client, convo, settings):
        settings.CHAT_MAX_ATTACHMENTS_PER_MESSAGE = 2
        r = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'hi', 'attachment_ids': [1, 2, 3]},
            format='json',
        )
        assert r.status_code == 400

    def test_invalid_attachment_ids_400(self, auth_client, convo):
        r = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'hi', 'attachment_ids': [99999]},
            format='json',
        )
        assert r.status_code == 400

    def test_cannot_use_other_users_attachment(self, auth_client, other_client, convo):
        # other user uploads
        r = other_client.post(
            '/api/attachments/upload/',
            {'file': SimpleUploadedFile('x.png', b'\x89PNG', content_type='image/png')},
            format='multipart',
        )
        att_id = r.json()['id']
        # we try to send it from our convo
        r2 = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'hi', 'attachment_ids': [att_id]},
            format='json',
        )
        assert r2.status_code == 400

    def test_cannot_send_to_other_users_convo(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID)
        r = auth_client.post(f'/api/conversations/{c.id}/messages/', {'content': 'hi'}, format='json')
        assert r.status_code == 404

    def test_image_on_non_vision_model_400(self, auth_client, user, convo):
        # convo is on a non-vision default model. Upload image, attach, expect 400.
        png = bytes.fromhex('89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489')
        r = auth_client.post(
            '/api/attachments/upload/',
            {'file': SimpleUploadedFile('a.png', png, content_type='image/png')},
            format='multipart',
        )
        att_id = r.json()['id']
        r2 = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'look', 'attachment_ids': [att_id]},
            format='json',
        )
        assert r2.status_code == 400

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_model_override_persists_on_convo(self, mock_stream, auth_client, convo):
        # convo currently uses DEFAULT_MODEL_ID; override to a vision model
        m = next(iter(VISION_MODEL_IDS & MODEL_IDS))
        r = auth_client.post(
            f'/api/conversations/{convo.id}/messages/',
            {'content': 'hi', 'model_id': m},
            format='json',
        )
        _consume_sse(r)
        convo.refresh_from_db()
        assert convo.model_id == m

    @patch('chat.views._stream_nvidia')
    def test_history_truncated_by_char_budget(self, mock_stream, auth_client, convo, settings):
        # 5 prior messages, big enough to blow the budget.
        for i in range(5):
            Message.objects.create(conversation=convo, role='user', content=f'old-{i} ' + ('z' * 1000))
        mock_stream.side_effect = _stream_ok
        settings.CHAT_HISTORY_MAX_CHARS = 1500
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'new'}, format='json')
        _consume_sse(r)
        # _stream_nvidia is called with (model_id, history). History should be ≤ 3 messages
        # (newest few that fit in 1500 chars).
        sent_history = mock_stream.call_args[0][1]
        assert len(sent_history) <= 3
        # The newest message must be present.
        assert sent_history[-1]['content'].startswith('new') or sent_history[-1]['content'] == 'new'


@pytest.mark.django_db
class TestHealth:
    def test_health_no_auth(self, client):
        r = client.get('/api/health/')
        assert r.status_code == 200
        assert r.json()['status'] == 'ok'


@pytest.mark.django_db
class TestModelsList:
    def test_lists_models_authenticated(self, auth_client):
        r = auth_client.get('/api/models/')
        assert r.status_code == 200
        body = r.json()
        assert 'models' in body
        assert 'default' in body
        assert body['default'] == DEFAULT_MODEL_ID

    def test_unauthenticated_blocked(self, client):
        r = client.get('/api/models/')
        assert r.status_code in (401, 403)
