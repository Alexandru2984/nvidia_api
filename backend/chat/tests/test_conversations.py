"""Tests for conversation CRUD, send_message streaming, ownership."""
from unittest.mock import MagicMock, patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from chat.models import Attachment, Conversation, Message
from chat.models_catalog import DEFAULT_MODEL_ID, MODEL_IDS, VISION_MODEL_IDS
from chat.views import _stream_nvidia


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
        titles = [c['title'] for c in r.json()['results']]
        assert titles == ['mine']
        assert r.json()['counts'] == {'active': 1, 'archived': 0}

    def test_filters_archived_and_reports_owner_scoped_counts(
        self, auth_client, user, other_user,
    ):
        active = Conversation.objects.create(user=user, title='active', model_id=DEFAULT_MODEL_ID)
        archived = Conversation.objects.create(
            user=user,
            title='archived',
            model_id=DEFAULT_MODEL_ID,
            archived_at=timezone.now(),
        )
        Conversation.objects.create(
            user=other_user,
            title='other archived',
            model_id=DEFAULT_MODEL_ID,
            archived_at=timezone.now(),
        )

        default_body = auth_client.get('/api/conversations/').json()
        archived_body = auth_client.get('/api/conversations/?view=archived').json()
        all_body = auth_client.get('/api/conversations/?view=all').json()

        assert [item['id'] for item in default_body['results']] == [active.id]
        assert [item['id'] for item in archived_body['results']] == [archived.id]
        assert {item['id'] for item in all_body['results']} == {active.id, archived.id}
        assert archived_body['counts'] == {'active': 1, 'archived': 1}

    def test_pinned_conversations_sort_first(self, auth_client, user):
        regular = Conversation.objects.create(user=user, title='newer', model_id=DEFAULT_MODEL_ID)
        pinned = Conversation.objects.create(
            user=user, title='pinned', model_id=DEFAULT_MODEL_ID, is_pinned=True,
        )
        Conversation.objects.filter(pk=regular.pk).update(updated_at=timezone.now())

        body = auth_client.get('/api/conversations/').json()

        assert [item['id'] for item in body['results']] == [pinned.id, regular.id]
        assert body['results'][0]['is_pinned'] is True

    def test_rejects_invalid_view(self, auth_client):
        r = auth_client.get('/api/conversations/?view=trash')
        assert r.status_code == 400


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

    @patch('chat.views.unavailable_model_ids', return_value={DEFAULT_MODEL_ID})
    def test_default_falls_back_when_catalog_default_is_down(self, _unavailable, auth_client):
        r = auth_client.post('/api/conversations/', {}, format='json')
        assert r.status_code == 201
        assert r.json()['model_id'] != DEFAULT_MODEL_ID

    @patch('chat.views.unavailable_model_ids', return_value={DEFAULT_MODEL_ID})
    def test_explicit_unavailable_model_is_rejected(self, _unavailable, auth_client):
        r = auth_client.post('/api/conversations/', {'model_id': DEFAULT_MODEL_ID}, format='json')
        assert r.status_code == 409

    @patch('chat.views.unavailable_model_ids', return_value=set(MODEL_IDS))
    def test_create_fails_when_all_models_are_unavailable(self, _unavailable, auth_client):
        r = auth_client.post('/api/conversations/', {}, format='json')
        assert r.status_code == 503
        assert not Conversation.objects.exists()

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

    @patch('chat.views.unavailable_model_ids', return_value={DEFAULT_MODEL_ID})
    def test_patch_unavailable_model_rejected(self, _unavailable, auth_client, convo):
        replacement = next(model for model in MODEL_IDS if model != DEFAULT_MODEL_ID)
        convo.model_id = replacement
        convo.save(update_fields=['model_id'])
        r = auth_client.patch(
            f'/api/conversations/{convo.id}/', {'model_id': DEFAULT_MODEL_ID}, format='json',
        )
        assert r.status_code == 409
        convo.refresh_from_db()
        assert convo.model_id == replacement

    def test_delete(self, auth_client, convo):
        r = auth_client.delete(f'/api/conversations/{convo.id}/')
        assert r.status_code == 204
        assert not Conversation.objects.filter(pk=convo.id).exists()

    def test_cannot_delete_other_users(self, auth_client, other_user):
        c = Conversation.objects.create(user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID)
        r = auth_client.delete(f'/api/conversations/{c.id}/')
        assert r.status_code == 404

    def test_pin_archive_and_restore(self, auth_client, convo):
        pinned = auth_client.patch(
            f'/api/conversations/{convo.id}/', {'is_pinned': True}, format='json',
        )
        assert pinned.status_code == 200
        assert pinned.json()['is_pinned'] is True

        archived = auth_client.patch(
            f'/api/conversations/{convo.id}/', {'archived': True}, format='json',
        )
        assert archived.status_code == 200
        assert archived.json()['archived_at'] is not None
        assert archived.json()['is_pinned'] is False

        restored = auth_client.patch(
            f'/api/conversations/{convo.id}/', {'archived': False}, format='json',
        )
        assert restored.status_code == 200
        assert restored.json()['archived_at'] is None

    @pytest.mark.parametrize('field,value', [
        ('is_pinned', 'true'),
        ('is_pinned', 1),
        ('is_pinned', None),
        ('archived', 'false'),
        ('archived', 0),
        ('archived', None),
    ])
    def test_pin_and_archive_require_json_booleans(self, auth_client, convo, field, value):
        r = auth_client.patch(
            f'/api/conversations/{convo.id}/', {field: value}, format='json',
        )
        assert r.status_code == 400

    def test_cannot_pin_archived_conversation(self, auth_client, convo):
        convo.archived_at = timezone.now()
        convo.save(update_fields=['archived_at'])

        r = auth_client.patch(
            f'/api/conversations/{convo.id}/', {'is_pinned': True}, format='json',
        )

        assert r.status_code == 409
        convo.refresh_from_db()
        assert convo.is_pinned is False

    def test_cannot_modify_other_users_archive_state(self, auth_client, other_user):
        other = Conversation.objects.create(
            user=other_user, title='theirs', model_id=DEFAULT_MODEL_ID,
        )

        r = auth_client.patch(
            f'/api/conversations/{other.id}/', {'archived': True}, format='json',
        )

        assert r.status_code == 404
        other.refresh_from_db()
        assert other.archived_at is None


def _stream_ok(*args, **kwargs):
    yield ('chunk', 'Hello')
    yield ('chunk', ' world')
    yield ('usage', {'total_tokens': 10})


def _stream_error(*args, **kwargs):
    yield ('error', 'NVIDIA exploded')


def _stream_empty(*args, **kwargs):
    return
    yield  # pragma: no cover  (make this a generator)


class TestNvidiaStreamParser:
    @patch('chat.views.requests.post')
    def test_decodes_byte_sse_and_requests_terminal_usage(self, mock_post):
        response = MagicMock(status_code=200)
        response.iter_lines.return_value = [
            b'data: {"choices":[{"delta":{"content":"hello"}}]}',
            b'data: {"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}',
            b'data: [DONE]',
        ]
        mock_post.return_value.__enter__.return_value = response

        events = list(_stream_nvidia('test/model', [{'role': 'user', 'content': 'hi'}]))

        assert events == [
            ('chunk', 'hello'),
            ('usage', {'prompt_tokens': 2, 'completion_tokens': 1, 'total_tokens': 3}),
        ]
        payload = mock_post.call_args.kwargs['json']
        assert payload['stream_options'] == {'include_usage': True}

    @patch('chat.views.requests.post')
    def test_rejected_request_emits_zero_usage_to_release_reservation(self, mock_post):
        response = MagicMock(status_code=410)
        mock_post.return_value.__enter__.return_value = response
        assert list(_stream_nvidia('retired/model', [])) == [
            ('usage', {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0}),
            ('error', 'NVIDIA API error (410). Try again later.'),
        ]

    @patch('chat.views._stream_nvidia')
    def test_successful_stream_reconciles_token_reservation(
        self, mock_stream, auth_client, convo, user, settings,
    ):
        settings.AI_CHAT_TOKEN_RESERVATION = 100
        settings.AI_USER_DAILY_TOKEN_LIMIT = 10_000
        settings.AI_GLOBAL_DAILY_TOKEN_LIMIT = 20_000
        mock_stream.return_value = iter([
            ('chunk', 'ok'),
            ('usage', {'prompt_tokens': 8, 'completion_tokens': 2, 'total_tokens': 10}),
        ])

        response = auth_client.post(
            f'/api/conversations/{convo.id}/messages/', {'content': 'hi'}, format='json',
        )
        _consume_sse(response)

        usage = user.daily_ai_usage.get(day=timezone.localdate())
        assert (usage.prompt_tokens, usage.completion_tokens, usage.reserved_tokens) == (8, 2, 0)


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

    def test_combined_attachment_size_is_bounded(self, auth_client, convo, user, settings):
        settings.CHAT_MAX_ATTACHMENT_BYTES_PER_MESSAGE = 10
        att = Attachment.objects.create(user=user, file=SimpleUploadedFile('x.txt', b'01234567890'),
            original_name='x.txt', mime_type='text/plain', size=11, kind='document')
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/',
            {'content': 'hi', 'attachment_ids': [att.id]}, format='json')
        assert r.status_code == 400

    def test_combined_document_context_is_bounded(self, auth_client, convo, user, settings):
        settings.CHAT_MAX_DOCUMENT_CHARS_PER_MESSAGE = 10
        att = Attachment.objects.create(user=user, file=SimpleUploadedFile('x.txt', b'x'),
            original_name='x.txt', mime_type='text/plain', size=1, kind='document', extracted_text='x' * 11)
        r = auth_client.post(f'/api/conversations/{convo.id}/messages/',
            {'content': 'hi', 'attachment_ids': [att.id]}, format='json')
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
            {'file': SimpleUploadedFile('x.txt', b'test', content_type='text/plain')},
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

    @patch('chat.views.unavailable_model_ids', return_value={DEFAULT_MODEL_ID})
    def test_unavailable_model_blocks_before_budget_or_message_write(
        self, _unavailable, auth_client, convo, user,
    ):
        r = auth_client.post(
            f'/api/conversations/{convo.id}/messages/', {'content': 'hi'}, format='json',
        )
        assert r.status_code == 409
        assert not Message.objects.filter(conversation=convo).exists()
        assert not user.daily_ai_usage.exists()

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

    @patch('chat.views.unavailable_model_ids', return_value=set(MODEL_IDS))
    def test_all_models_unavailable_has_no_default(self, _unavailable, auth_client):
        r = auth_client.get('/api/models/')
        assert r.status_code == 200
        assert r.json()['models'] == []
        assert r.json()['default'] is None

    def test_unauthenticated_blocked(self, client):
        r = client.get('/api/models/')
        assert r.status_code in (401, 403)


@pytest.mark.django_db
class TestConversationSearch:
    def _mk(self, user, title, msg=None):
        c = Conversation.objects.create(user=user, title=title, model_id=DEFAULT_MODEL_ID)
        if msg:
            Message.objects.create(conversation=c, role='user', content=msg)
        return c

    def test_search_by_title(self, auth_client, user):
        self._mk(user, 'Django tips')
        self._mk(user, 'Cooking pasta')
        r = auth_client.get('/api/conversations/?q=django')
        assert [c['title'] for c in r.json()['results']] == ['Django tips']

    def test_search_by_message_content(self, auth_client, user):
        self._mk(user, 'Untitled A', msg='how do I use gunicorn workers?')
        self._mk(user, 'Untitled B', msg='banana bread recipe')
        r = auth_client.get('/api/conversations/?q=gunicorn')
        assert [c['title'] for c in r.json()['results']] == ['Untitled A']

    def test_search_does_not_leak_other_users(self, auth_client, user, other_user):
        self._mk(other_user, 'Secret gunicorn talk', msg='gunicorn secrets')
        r = auth_client.get('/api/conversations/?q=gunicorn')
        assert r.json()['results'] == []

    def test_search_no_duplicates_when_title_and_content_match(self, auth_client, user):
        self._mk(user, 'gunicorn', msg='more gunicorn text')
        r = auth_client.get('/api/conversations/?q=gunicorn')
        assert len(r.json()['results']) == 1

    def test_empty_q_returns_all(self, auth_client, user):
        self._mk(user, 'One')
        self._mk(user, 'Two')
        r = auth_client.get('/api/conversations/?q=')
        assert len(r.json()['results']) == 2

    def test_search_stays_within_selected_view(self, auth_client, user):
        self._mk(user, 'active match')
        archived = self._mk(user, 'archived match')
        archived.archived_at = timezone.now()
        archived.save(update_fields=['archived_at'])

        active_results = auth_client.get('/api/conversations/?q=match').json()['results']
        archived_results = auth_client.get(
            '/api/conversations/?q=match&view=archived',
        ).json()['results']

        assert [item['title'] for item in active_results] == ['active match']
        assert [item['title'] for item in archived_results] == ['archived match']


@pytest.mark.django_db
class TestConversationGenSettings:
    def test_patch_sets_all_fields(self, auth_client, convo):
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {
            'system_prompt': '  You are terse.  ',
            'temperature': 1.3,
            'max_tokens': 2048,
        }, format='json')
        assert r.status_code == 200, r.content
        body = r.json()
        assert body['system_prompt'] == 'You are terse.'
        assert body['temperature'] == 1.3
        assert body['max_tokens'] == 2048

    def test_temperature_out_of_range_400(self, auth_client, convo):
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {'temperature': 2.5}, format='json')
        assert r.status_code == 400
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {'temperature': 'hot'}, format='json')
        assert r.status_code == 400

    def test_max_tokens_out_of_range_400(self, auth_client, convo):
        assert auth_client.patch(f'/api/conversations/{convo.id}/', {'max_tokens': 10}, format='json').status_code == 400
        assert auth_client.patch(f'/api/conversations/{convo.id}/', {'max_tokens': 999999}, format='json').status_code == 400

    def test_system_prompt_too_long_400(self, auth_client, convo):
        r = auth_client.patch(f'/api/conversations/{convo.id}/', {'system_prompt': 'x' * 4001}, format='json')
        assert r.status_code == 400

    def test_system_prompt_and_params_reach_nvidia(self, auth_client, convo):
        convo.system_prompt = 'You are terse.'
        convo.temperature = 0.2
        convo.max_tokens = 512
        convo.save()
        captured = {}

        def spy(model_id, messages, **kw):
            captured['messages'] = messages
            captured['kw'] = kw
            yield ('chunk', 'ok')

        with patch('chat.views._stream_nvidia', side_effect=spy):
            r = auth_client.post(f'/api/conversations/{convo.id}/messages/', {'content': 'hi'}, format='json')
            _consume_sse(r)
        assert captured['messages'][0] == {'role': 'system', 'content': 'You are terse.'}
        assert captured['kw'] == {'max_tokens': 512, 'temperature': 0.2}

    def test_regenerate_uses_system_prompt(self, auth_client, convo):
        convo.system_prompt = 'Speak like a pirate.'
        convo.save()
        u = Message.objects.create(conversation=convo, role='user', content='hi')
        Message.objects.create(conversation=convo, role='assistant', content='hello')
        captured = {}

        def spy(model_id, messages, **kw):
            captured['messages'] = messages
            yield ('chunk', 'arr')

        with patch('chat.views._stream_nvidia', side_effect=spy):
            r = auth_client.post(f'/api/messages/{u.id}/regenerate/')
            _consume_sse(r)
        assert captured['messages'][0]['role'] == 'system'
