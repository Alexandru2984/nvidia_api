"""PostgreSQL attachment claim versus deletion/expiry interleavings."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from io import StringIO
from pathlib import Path

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import connection, transaction
from django.utils import timezone
from rest_framework.test import APIClient

from chat.models import Attachment, Message, PendingFileDeletion
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
