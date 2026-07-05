"""Client-side abort (Stop button): the partial reply must be persisted."""
from unittest.mock import patch

import pytest

from chat.models import Conversation, Message


def _stream_many(model_id, messages, **kw):
    yield ('chunk', 'Hello ')
    yield ('chunk', 'brave ')
    yield ('chunk', 'new world')
    yield ('usage', {'total_tokens': 5})


@pytest.mark.django_db
class TestStopGeneration:
    def test_abort_mid_stream_saves_partial(self, auth_client, convo):
        with patch('chat.views._stream_nvidia', side_effect=_stream_many):
            r = auth_client.post(
                f'/api/conversations/{convo.id}/messages/',
                {'content': 'tell me a story'}, format='json',
            )
            it = iter(r.streaming_content)
            next(it)  # user_message event
            next(it)  # first chunk streamed to the client
            r.close()  # client disconnects → GeneratorExit inside event_stream

        msgs = list(convo.messages.order_by('created_at'))
        assert [m.role for m in msgs] == ['user', 'assistant']
        assert msgs[1].content == 'Hello '

    def test_abort_mid_stream_titles_new_chat(self, auth_client, user):
        convo = Conversation.objects.create(user=user, title='New Chat', model_id='meta/llama-3.1-8b-instruct')
        with patch('chat.views._stream_nvidia', side_effect=_stream_many):
            r = auth_client.post(
                f'/api/conversations/{convo.id}/messages/',
                {'content': 'tell me a story'}, format='json',
            )
            it = iter(r.streaming_content)
            next(it)
            next(it)
            r.close()
        convo.refresh_from_db()
        assert convo.title.startswith('tell me a story')

    def test_abort_before_any_chunk_rolls_back_user_message(self, auth_client, convo):
        with patch('chat.views._stream_nvidia', side_effect=_stream_many):
            r = auth_client.post(
                f'/api/conversations/{convo.id}/messages/',
                {'content': 'tell me a story'}, format='json',
            )
            it = iter(r.streaming_content)
            next(it)  # only the user_message event; no chunks yet
            r.close()

        assert convo.messages.count() == 0

    def test_abort_regenerate_saves_partial(self, auth_client, convo, user):
        Message.objects.create(conversation=convo, role='user', content='hi')
        old = Message.objects.create(conversation=convo, role='assistant', content='old reply')
        with patch('chat.views._stream_nvidia', side_effect=_stream_many):
            r = auth_client.post(f'/api/messages/{old.id}/regenerate/')
            it = iter(r.streaming_content)
            next(it)  # first chunk
            r.close()

        msgs = list(convo.messages.order_by('created_at'))
        assert [m.role for m in msgs] == ['user', 'assistant']
        assert msgs[1].content == 'Hello '
        assert msgs[1].id != old.id
