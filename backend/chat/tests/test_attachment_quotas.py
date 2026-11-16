"""Attachment inode, total-byte and upload-coordination admission boundaries."""
import base64
import uuid
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.response import Response

from chat.models import Attachment, AttachmentUploadAttempt
from chat.tests.test_images import PNG_1PX


pytestmark = pytest.mark.django_db


def _upload(client, text='file', attempt_id=None):
    data = {'file': SimpleUploadedFile('note.txt', text.encode(), content_type='text/plain')}
    if attempt_id:
        data['upload_attempt_id'] = str(attempt_id)
    return client.post('/api/attachments/upload/', data, format='multipart')


def _stored(user, size=1):
    return Attachment.objects.create(
        user=user, file=f'attachments/{user.pk}/{uuid.uuid4().hex}/note.txt',
        original_name='note.txt', mime_type='text/plain', size=size,
        kind=Attachment.KIND_DOCUMENT,
    )


def test_tiny_files_hit_object_limit_before_byte_limit(auth_client, settings):
    settings.MAX_USER_ATTACHMENTS = 2
    assert _upload(auth_client, 'a').status_code == 201
    assert _upload(auth_client, 'b').status_code == 201

    blocked = _upload(auth_client, 'c')

    assert blocked.status_code == 413
    assert blocked.json()['code'] == 'attachment_limit'
    assert Attachment.objects.count() == 2


def test_file_limit_is_owner_scoped(auth_client, other_client, settings):
    settings.MAX_USER_ATTACHMENTS = 1
    assert _upload(auth_client, 'a').status_code == 201
    assert _upload(other_client, 'b').status_code == 201
    assert _upload(auth_client, 'c').status_code == 413


@pytest.mark.parametrize('resource', ['files', 'bytes'])
def test_service_capacity_is_shared_and_not_exposed(auth_client, other_client, settings, resource):
    if resource == 'files':
        settings.MAX_GLOBAL_ATTACHMENTS = 1
    else:
        settings.MAX_GLOBAL_STORAGE = 6
    assert _upload(auth_client, '123456').status_code == 201

    blocked = _upload(other_client, 'abcdef')

    assert blocked.status_code == 503
    assert blocked.json()['code'] == 'attachment_capacity_unavailable'
    assert 'used' not in blocked.json() and 'limit' not in blocked.json()
    assert blocked['Retry-After'] == '60'
    assert Attachment.objects.count() == 1


def test_duplicate_and_attempt_replay_work_at_capacity(auth_client, settings):
    settings.MAX_USER_ATTACHMENTS = 1
    settings.MAX_GLOBAL_ATTACHMENTS = 1
    settings.MAX_USER_UPLOAD_ATTEMPTS = 1
    attempt_id = uuid.uuid4()
    first = _upload(auth_client, 'same', attempt_id)
    assert first.status_code == 201

    replay = _upload(auth_client, 'same', attempt_id)
    duplicate = _upload(auth_client, 'same')

    assert replay.status_code == duplicate.status_code == 200
    assert replay.json()['id'] == duplicate.json()['id'] == first.json()['id']


def test_user_attempt_capacity_still_allows_existing_cancellation(auth_client, settings):
    settings.MAX_USER_UPLOAD_ATTEMPTS = 1
    attempt_id = uuid.uuid4()
    first = _upload(auth_client, 'first', attempt_id)
    assert first.status_code == 201

    blocked = auth_client.delete(f'/api/attachments/upload/{uuid.uuid4()}/')
    canceled = auth_client.delete(f'/api/attachments/upload/{attempt_id}/')

    assert blocked.status_code == 413
    assert blocked.json()['code'] == 'upload_attempt_limit'
    assert canceled.status_code == 204
    assert AttachmentUploadAttempt.objects.count() == 1
    assert not Attachment.objects.exists()


def test_new_upload_attempt_is_bounded(auth_client, settings):
    settings.MAX_USER_UPLOAD_ATTEMPTS = 1
    assert _upload(auth_client, 'first', uuid.uuid4()).status_code == 201

    blocked = _upload(auth_client, 'second', uuid.uuid4())

    assert blocked.status_code == 413
    assert AttachmentUploadAttempt.objects.count() == 1
    assert Attachment.objects.count() == 1


def test_global_attempt_limit_is_shared(auth_client, other_client, settings):
    settings.MAX_GLOBAL_UPLOAD_ATTEMPTS = 1
    assert auth_client.delete(f'/api/attachments/upload/{uuid.uuid4()}/').status_code == 204

    blocked = other_client.delete(f'/api/attachments/upload/{uuid.uuid4()}/')

    assert blocked.status_code == 503
    assert blocked.json()['code'] == 'attachment_capacity_unavailable'
    assert AttachmentUploadAttempt.objects.count() == 1


def test_image_count_limit_blocks_before_provider_budget(auth_client, user, settings):
    settings.MAX_USER_ATTACHMENTS = 1
    _stored(user)
    with patch('chat.views._reserve_provider_call', return_value=None) as reserve:
        with patch('chat.views._nvcf_generate', return_value=(None, Response(status=502))) as generate:
            blocked = auth_client.post('/api/images/generate/', {'prompt': 'example'}, format='json')

    assert blocked.status_code == 413
    reserve.assert_not_called()
    generate.assert_not_called()


def test_usage_exposes_only_owner_file_limit(auth_client, user, other_user, settings):
    settings.MAX_USER_ATTACHMENTS = 23
    _stored(user)
    _stored(other_user)

    payload = auth_client.get('/api/account/usage/').json()

    assert payload['attachments'] == 1
    assert payload['attachment_limit'] == 23
    assert 'global_attachments' not in payload


def test_deletion_frees_file_capacity(auth_client, settings):
    settings.MAX_USER_ATTACHMENTS = 1
    first = _upload(auth_client, 'first')
    assert first.status_code == 201
    assert _upload(auth_client, 'blocked').status_code == 413
    assert auth_client.delete(f'/api/attachments/{first.json()["id"]}/').status_code == 204
    assert _upload(auth_client, 'replacement').status_code == 201


@pytest.mark.parametrize('kind', [Attachment.KIND_DOCUMENT, Attachment.KIND_GENERATED])
def test_linked_and_generated_files_still_consume_capacity(auth_client, user, convo, settings, kind):
    from chat.models import Message

    settings.MAX_USER_ATTACHMENTS = 1
    stored = _stored(user)
    stored.kind = kind
    stored.message = Message.objects.create(conversation=convo, role='user', content='linked')
    stored.save(update_fields=['kind', 'message'])

    assert _upload(auth_client, 'another').status_code == 413


@pytest.mark.parametrize('scope', ['user', 'global'])
def test_image_rechecks_capacity_after_provider_call(auth_client, user, other_user, settings, scope):
    if scope == 'user':
        settings.MAX_USER_ATTACHMENTS = 1
    else:
        settings.MAX_GLOBAL_STORAGE = len(PNG_1PX)

    def provider_result(*args, **kwargs):
        # Another request commits while the provider is generating the image.
        _stored(user if scope == 'user' else other_user)
        return {'image': base64.b64encode(PNG_1PX).decode()}, None

    with patch('chat.views._nvcf_generate', side_effect=provider_result):
        blocked = auth_client.post('/api/images/generate/', {'prompt': 'example'}, format='json')

    assert blocked.status_code == (413 if scope == 'user' else 503)
    assert Attachment.objects.count() == 1
    assert not Attachment.objects.filter(kind=Attachment.KIND_GENERATED).exists()


def test_quota_event_does_not_include_private_file_content(auth_client, settings, caplog):
    settings.MAX_USER_ATTACHMENTS = 0
    private_marker = 'private-file-content-marker'

    with caplog.at_level('WARNING', logger='security'):
        blocked = _upload(auth_client, private_marker)

    assert blocked.status_code == 413
    assert 'event=attachment_quota_blocked scope=user resource=files' in caplog.text
    assert private_marker not in caplog.text
    assert 'note.txt' not in caplog.text
