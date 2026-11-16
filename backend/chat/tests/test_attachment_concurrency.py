"""PostgreSQL attachment claim versus deletion/expiry interleavings."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from io import StringIO
from pathlib import Path
import threading
import uuid
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import connection, transaction
from django.db.models import Sum
from django.utils import timezone
from rest_framework.test import APIClient

from chat.models import Attachment, AttachmentUploadAttempt, ChatStorageGate, Message, PendingFileDeletion
from chat.tests.test_security_concurrency import _wait_for_lock_or_completion, _worker


pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(connection.vendor != 'postgresql', reason='requires PostgreSQL row locks'),
]


@pytest.mark.parametrize('deletion', ['user_delete', 'ttl'])
def test_claimed_attachment_survives_concurrent_deletion(user, convo, deletion):
    attachment = Attachment.objects.create(
        user=user,
        file=SimpleUploadedFile('private.txt', b'private', content_type='text/plain'),
        original_name='private.txt', mime_type='text/plain', size=7,
        kind=Attachment.KIND_DOCUMENT,
    )
    path = Path(attachment.file.path)
    Attachment.objects.filter(pk=attachment.pk).update(
        created_at=timezone.now() - timedelta(days=settings.ATTACHMENT_TTL_DAYS + 1),
    )
    message = Message.objects.create(conversation=convo, role='user', content='claimed')
    output = StringIO()

    def delete():
        if deletion == 'ttl':
            call_command('cleanup_attachments', stdout=output)
            return None
        client = APIClient()
        # Model a request already authenticated before the claim transaction;
        # session-inventory locks must not mask missing locks in the view.
        client.force_authenticate(user=user)
        return client.delete(f'/api/attachments/{attachment.pk}/')

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            get_user_model().objects.select_for_update().get(pk=user.pk)
            deletion_call = executor.submit(_worker, delete)
            try:
                blocked = _wait_for_lock_or_completion(deletion_call)
            finally:
                # Match the security-relevant part of send_message's claim:
                # owner -> attachment, followed by a durable message binding.
                Attachment.objects.select_for_update().filter(pk=attachment.pk).update(
                    message=message,
                )
        response = deletion_call.result(timeout=10)

    assert blocked, 'deletion bypassed the in-flight owner/attachment claim'
    attachment.refresh_from_db()
    assert attachment.message_id == message.pk
    assert path.exists()
    assert not PendingFileDeletion.objects.exists()
    if deletion == 'user_delete':
        assert response.status_code == 409
    else:
        assert 'Deleted 0 orphan attachments' in output.getvalue()


@pytest.mark.parametrize('resource', ['user_files', 'global_files', 'global_bytes'])
def test_parallel_uploads_cannot_overrun_last_slot(user, other_user, settings, resource):
    ChatStorageGate.objects.get_or_create(pk=1)
    if resource == 'user_files':
        settings.MAX_USER_ATTACHMENTS = 1
    elif resource == 'global_files':
        settings.MAX_GLOBAL_ATTACHMENTS = 1
    else:
        settings.MAX_GLOBAL_STORAGE = 6
    owners = [user, user if resource == 'user_files' else other_user]
    parsed = threading.Barrier(2)

    def extract(upload, mime):
        # Both requests must pass the coarse quota check before either saves.
        parsed.wait(timeout=10)
        return 'readable text'

    def upload(owner, content):
        client = APIClient()
        client.force_authenticate(user=owner)
        return client.post('/api/attachments/upload/', {
            'file': SimpleUploadedFile('file.txt', content, content_type='text/plain'),
        }, format='multipart')

    with patch('chat.views.extract_text', side_effect=extract):
        with ThreadPoolExecutor(max_workers=2) as executor:
            calls = [executor.submit(_worker, lambda owner=owner, content=content: upload(owner, content))
                     for owner, content in zip(owners, [b'123456', b'abcdef'])]
            responses = [call.result(timeout=15) for call in calls]

    assert sorted(response.status_code for response in responses) == [201, 413 if resource == 'user_files' else 503]
    assert Attachment.objects.count() == 1
    assert Attachment.objects.aggregate(total=Sum('size'))['total'] == 6


@pytest.mark.parametrize('endpoint', ['cancel', 'upload'])
def test_attempt_creation_waits_for_global_capacity_transaction(user, other_user, settings, endpoint):
    ChatStorageGate.objects.get_or_create(pk=1)
    settings.MAX_GLOBAL_UPLOAD_ATTEMPTS = 1
    client = APIClient()
    client.force_authenticate(user=other_user)
    attempt_id = uuid.uuid4()

    def allocate():
        if endpoint == 'cancel':
            return client.delete(f'/api/attachments/upload/{attempt_id}/')
        return client.post('/api/attachments/upload/', {
            'file': SimpleUploadedFile('file.txt', b'body', content_type='text/plain'),
            'upload_attempt_id': str(attempt_id),
        }, format='multipart')

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            ChatStorageGate.objects.select_for_update().get(pk=1)
            call = executor.submit(_worker, allocate)
            try:
                blocked = _wait_for_lock_or_completion(call)
            finally:
                AttachmentUploadAttempt.objects.create(id=uuid.uuid4(), user=user)
        response = call.result(timeout=10)

    assert blocked, 'attempt allocation bypassed the service-wide admission lock'
    assert response.status_code == 503
    assert AttachmentUploadAttempt.objects.count() == 1
    assert not Attachment.objects.exists()
