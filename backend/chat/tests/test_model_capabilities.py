"""Capability contracts for model selection and attachment delivery."""
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from chat.models import Attachment, Conversation, Message
from chat.models_catalog import (
    DEFAULT_MODEL_ID,
    MODEL_IDS,
    VISION_MODEL_IDS,
    model_capabilities,
)

pytestmark = pytest.mark.django_db

PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489'
)
VISION_MODEL = 'meta/llama-3.2-11b-vision-instruct'
SAFETY_MODEL = 'nvidia/llama-3.1-nemotron-safety-guard-8b-v3'
ASSISTANT_MODEL = 'nvidia/nemotron-3-super-120b-a12b'


def _image(name='image.png'):
    return SimpleUploadedFile(name, PNG, content_type='image/png')


def _attachment(user, name='image.png', message=None):
    return Attachment.objects.create(
        user=user,
        message=message,
        file=_image(name),
        original_name=name,
        mime_type='image/png',
        size=len(PNG),
        kind=Attachment.KIND_IMAGE,
    )


def _consume(response):
    return b''.join(response.streaming_content).decode()


def _capturing_stream(target):
    def stream(model_id, messages, **kwargs):
        target['model_id'] = model_id
        target['messages'] = messages
        yield ('chunk', 'ok')
        yield ('usage', {'prompt_tokens': 2, 'completion_tokens': 1, 'total_tokens': 3})

    return stream


def test_catalog_exposes_conservative_capabilities():
    assert 'meta/llama-4-scout-17b-16e-instruct' not in VISION_MODEL_IDS
    assert 'nvidia/nemotron-nano-12b-v2-vl' in VISION_MODEL_IDS
    assert model_capabilities(DEFAULT_MODEL_ID) == {
        'input_modalities': ['text', 'document'],
        'attachment_extensions': ['pdf', 'txt', 'md', 'docx'],
        'document_extensions': ['pdf', 'txt', 'md', 'docx'],
        'documents_as_text': True,
        'image_mime_types': [],
        'max_images': 0,
        'max_image_bytes': None,
    }
    nano_vl = model_capabilities('nvidia/nemotron-nano-12b-v2-vl')
    assert nano_vl['max_images'] == 5
    assert nano_vl['image_mime_types'] == ['image/jpeg', 'image/png', 'image/webp']


@patch('chat.views.unavailable_model_ids')
def test_models_endpoint_prefers_assistant_over_specialized_model(mock_down, auth_client):
    mock_down.return_value = MODEL_IDS - {SAFETY_MODEL, ASSISTANT_MODEL}

    response = auth_client.get('/api/models/')

    assert response.status_code == 200
    body = response.json()
    assert body['default'] == ASSISTANT_MODEL
    assert body['attachment_limits']['max_files_per_message'] > 0
    returned = {model['id']: model for model in body['models']}
    assert returned[SAFETY_MODEL]['purpose'] == 'safety'
    assert returned[SAFETY_MODEL]['recommended'] is False
    assert returned[ASSISTANT_MODEL]['purpose'] == 'assistant'
    assert 'capabilities' in returned[ASSISTANT_MODEL]


def test_upload_rejects_image_for_text_only_model(auth_client):
    response = auth_client.post(
        '/api/attachments/upload/',
        {'file': _image(), 'model_id': DEFAULT_MODEL_ID},
        format='multipart',
    )

    assert response.status_code == 400
    assert response.json()['code'] == 'images_not_supported'
    assert not Attachment.objects.exists()


def test_upload_rejects_model_incompatible_image_format(auth_client):
    webp = SimpleUploadedFile(
        'image.webp', b'RIFF' + b'\x08\x00\x00\x00' + b'WEBP' + b'VP8 ',
        content_type='image/webp',
    )

    response = auth_client.post(
        '/api/attachments/upload/',
        {'file': webp, 'model_id': VISION_MODEL},
        format='multipart',
    )

    assert response.status_code == 400
    assert response.json()['code'] == 'image_format_unsupported'
    assert not Attachment.objects.exists()


def test_upload_rejects_document_without_extracted_text(auth_client):
    response = auth_client.post(
        '/api/attachments/upload/',
        {
            'file': SimpleUploadedFile('blank.txt', b'   ', content_type='text/plain'),
            'model_id': DEFAULT_MODEL_ID,
        },
        format='multipart',
    )

    assert response.status_code == 422
    assert response.json()['code'] == 'document_text_unavailable'
    assert not Attachment.objects.exists()


def test_send_rejects_too_many_images_for_model(auth_client, user):
    conversation = Conversation.objects.create(
        user=user, title='vision', model_id=VISION_MODEL,
    )
    attachments = [_attachment(user, 'first.png'), _attachment(user, 'second.png')]

    response = auth_client.post(
        f'/api/conversations/{conversation.pk}/messages/',
        {'content': 'compare', 'attachment_ids': [item.pk for item in attachments]},
        format='json',
    )

    assert response.status_code == 400
    assert response.json()['code'] == 'too_many_images_for_model'
    assert not conversation.messages.exists()


def test_failed_override_does_not_change_conversation_model(auth_client, user):
    conversation = Conversation.objects.create(
        user=user, title='vision', model_id=VISION_MODEL,
    )
    image = _attachment(user)

    response = auth_client.post(
        f'/api/conversations/{conversation.pk}/messages/',
        {'content': 'look', 'attachment_ids': [image.pk], 'model_id': DEFAULT_MODEL_ID},
        format='json',
    )

    assert response.status_code == 400
    assert response.json()['code'] == 'images_not_supported'
    conversation.refresh_from_db()
    assert conversation.model_id == VISION_MODEL


@patch('chat.views._stream_nvidia')
def test_text_model_omits_historical_images(mock_stream, auth_client, user, convo):
    old_message = Message.objects.create(conversation=convo, role='user', content='old image')
    _attachment(user, message=old_message)
    captured = {}
    mock_stream.side_effect = _capturing_stream(captured)

    response = auth_client.post(
        f'/api/conversations/{convo.pk}/messages/', {'content': 'continue'}, format='json',
    )
    _consume(response)

    assert all(isinstance(message['content'], str) for message in captured['messages'])
    assert not any('data:image/' in message['content'] for message in captured['messages'])


@patch('chat.views._stream_nvidia')
def test_vision_history_keeps_only_newest_images_within_limit(mock_stream, auth_client, user):
    conversation = Conversation.objects.create(
        user=user, title='vision', model_id=VISION_MODEL,
    )
    old_message = Message.objects.create(conversation=conversation, role='user', content='old')
    _attachment(user, 'old.png', old_message)
    current = _attachment(user, 'current.png')
    captured = {}
    mock_stream.side_effect = _capturing_stream(captured)

    response = auth_client.post(
        f'/api/conversations/{conversation.pk}/messages/',
        {'content': 'new', 'attachment_ids': [current.pk]},
        format='json',
    )
    _consume(response)

    image_parts = [
        part
        for message in captured['messages']
        if isinstance(message['content'], list)
        for part in message['content']
        if part['type'] == 'image_url'
    ]
    assert len(image_parts) == 1


@patch('chat.views._stream_nvidia')
def test_documents_are_injected_as_text_for_text_model(mock_stream, auth_client, user, convo):
    document = Attachment.objects.create(
        user=user,
        file=SimpleUploadedFile('notes.txt', b'private notes', content_type='text/plain'),
        original_name='notes.txt',
        mime_type='text/plain',
        size=13,
        kind=Attachment.KIND_DOCUMENT,
        extracted_text='private notes',
    )
    captured = {}
    mock_stream.side_effect = _capturing_stream(captured)

    response = auth_client.post(
        f'/api/conversations/{convo.pk}/messages/',
        {'content': 'summarize', 'attachment_ids': [document.pk]},
        format='json',
    )
    _consume(response)

    assert captured['messages'][-1]['content'].startswith('[Document: notes.txt]')
    assert 'private notes' in captured['messages'][-1]['content']
