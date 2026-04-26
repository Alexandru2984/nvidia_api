"""Tests for export, message edit, and regenerate."""
from unittest.mock import patch

import pytest

from chat.models import Conversation, Message
from chat.models_catalog import DEFAULT_MODEL_ID


def _consume_sse(response):
    return b''.join(response.streaming_content).decode()


@pytest.fixture
def populated_convo(user):
    c = Conversation.objects.create(user=user, title='Hello world', model_id=DEFAULT_MODEL_ID)
    Message.objects.create(conversation=c, role='user', content='hi there')
    Message.objects.create(conversation=c, role='assistant', content='hello back')
    Message.objects.create(conversation=c, role='user', content='how are you?')
    Message.objects.create(conversation=c, role='assistant', content='good thanks')
    return c


@pytest.mark.django_db
class TestExportConversation:
    def test_export_returns_markdown(self, auth_client, populated_convo):
        r = auth_client.get(f'/api/conversations/{populated_convo.id}/export/')
        assert r.status_code == 200
        assert r['Content-Type'].startswith('text/markdown')
        body = r.content.decode()
        assert '# Hello world' in body
        assert 'hi there' in body
        assert 'hello back' in body
        assert 'how are you?' in body
        assert 'good thanks' in body
        assert f'`{DEFAULT_MODEL_ID}`' in body

    def test_export_includes_attachment_filenames(self, auth_client, user, populated_convo):
        from django.core.files.uploadedfile import SimpleUploadedFile
        from chat.models import Attachment
        first_user_msg = populated_convo.messages.filter(role='user').first()
        a = Attachment.objects.create(
            user=user,
            file=SimpleUploadedFile('chart.png', b'png', content_type='image/png'),
            original_name='chart.png', mime_type='image/png', size=3, kind='image',
            message=first_user_msg,
        )
        r = auth_client.get(f'/api/conversations/{populated_convo.id}/export/')
        body = r.content.decode()
        assert 'chart.png' in body

    def test_export_filename_in_header(self, auth_client, populated_convo):
        r = auth_client.get(f'/api/conversations/{populated_convo.id}/export/')
        cd = r['Content-Disposition']
        assert 'attachment' in cd
        assert '.md' in cd

    def test_cannot_export_other_users(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID)
        r = auth_client.get(f'/api/conversations/{c.id}/export/')
        assert r.status_code == 404


@pytest.mark.django_db
class TestEditMessage:
    def test_edit_user_message(self, auth_client, populated_convo):
        msg = populated_convo.messages.filter(role='user').first()
        r = auth_client.patch(f'/api/messages/{msg.id}/', {'content': 'edited'}, format='json')
        assert r.status_code == 200
        msg.refresh_from_db()
        assert msg.content == 'edited'

    def test_cannot_edit_assistant_message(self, auth_client, populated_convo):
        msg = populated_convo.messages.filter(role='assistant').first()
        r = auth_client.patch(f'/api/messages/{msg.id}/', {'content': 'tampered'}, format='json')
        assert r.status_code == 400
        msg.refresh_from_db()
        assert msg.content == 'hello back'  # unchanged

    def test_edit_empty_content_400(self, auth_client, populated_convo):
        msg = populated_convo.messages.filter(role='user').first()
        r = auth_client.patch(f'/api/messages/{msg.id}/', {'content': ''}, format='json')
        assert r.status_code == 400

    def test_edit_too_long_400(self, auth_client, populated_convo, settings):
        settings.CHAT_MAX_MESSAGE_CHARS = 10
        msg = populated_convo.messages.filter(role='user').first()
        r = auth_client.patch(f'/api/messages/{msg.id}/', {'content': 'x' * 50}, format='json')
        assert r.status_code == 400

    def test_cannot_edit_other_users_message(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='t', model_id=DEFAULT_MODEL_ID)
        m = Message.objects.create(conversation=c, role='user', content='hi')
        r = auth_client.patch(f'/api/messages/{m.id}/', {'content': 'edit'}, format='json')
        assert r.status_code == 404


def _stream_ok(*args, **kwargs):
    yield ('chunk', 'New ')
    yield ('chunk', 'reply')
    yield ('usage', {'total_tokens': 5})


def _stream_error(*args, **kwargs):
    yield ('error', 'NVIDIA exploded')


def _stream_empty(*args, **kwargs):
    return
    yield  # pragma: no cover


@pytest.mark.django_db
class TestRegenerateMessage:
    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_regenerate_assistant_replaces_it(self, mock_stream, auth_client, populated_convo):
        # 4 messages: user, assistant, user, assistant. Regenerate the last assistant.
        last_assistant = populated_convo.messages.filter(role='assistant').last()
        r = auth_client.post(f'/api/messages/{last_assistant.id}/regenerate/')
        assert r.status_code == 200
        _consume_sse(r)
        # Old assistant message gone
        assert not Message.objects.filter(pk=last_assistant.id).exists()
        # New assistant present
        new = populated_convo.messages.filter(role='assistant').last()
        assert new.content == 'New reply'
        # Total: user, assistant, user, NEW_assistant
        assert populated_convo.messages.count() == 4

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_regenerate_first_assistant_truncates_later(self, mock_stream, auth_client, populated_convo):
        # Regenerate the FIRST assistant message → must drop the 2nd user + 2nd assistant too.
        first_assistant = populated_convo.messages.filter(role='assistant').first()
        r = auth_client.post(f'/api/messages/{first_assistant.id}/regenerate/')
        _consume_sse(r)
        # Should be: user "hi there" + new assistant
        assert populated_convo.messages.count() == 2
        assert populated_convo.messages.filter(role='user').first().content == 'hi there'

    @patch('chat.views._stream_nvidia', side_effect=_stream_ok)
    def test_regenerate_user_message_keeps_user_drops_later(self, mock_stream, auth_client, populated_convo):
        # Pick second user message: "how are you?". Regenerate from there.
        second_user = populated_convo.messages.filter(role='user').last()
        r = auth_client.post(f'/api/messages/{second_user.id}/regenerate/')
        _consume_sse(r)
        # The user message stays; later (last assistant) is replaced.
        assert populated_convo.messages.filter(pk=second_user.id).exists()
        last = populated_convo.messages.filter(role='assistant').last()
        assert last.content == 'New reply'

    @patch('chat.views._stream_nvidia', side_effect=_stream_error)
    def test_regenerate_error_yields_error_event(self, mock_stream, auth_client, populated_convo):
        last_assistant = populated_convo.messages.filter(role='assistant').last()
        r = auth_client.post(f'/api/messages/{last_assistant.id}/regenerate/')
        body = _consume_sse(r)
        assert 'error' in body.lower()

    def test_cannot_regenerate_other_users(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='t', model_id=DEFAULT_MODEL_ID)
        m = Message.objects.create(conversation=c, role='assistant', content='hi')
        r = auth_client.post(f'/api/messages/{m.id}/regenerate/')
        assert r.status_code == 404

    def test_regenerate_assistant_with_no_prior_user_400(self, auth_client, user):
        # An orphan assistant message with no user before it.
        c = Conversation.objects.create(user=user, title='t', model_id=DEFAULT_MODEL_ID)
        m = Message.objects.create(conversation=c, role='assistant', content='odd')
        r = auth_client.post(f'/api/messages/{m.id}/regenerate/')
        assert r.status_code == 400
