"""Durable attachment-file deletion outbox coverage."""
import uuid
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from chat.models import Attachment, PendingFileDeletion


@pytest.mark.django_db
def test_committed_storage_failure_is_private_and_retried(
    user,
    django_capture_on_commit_callbacks,
    caplog,
):
    caplog.set_level('ERROR', logger='security')
    attachment = Attachment.objects.create(
        user=user,
        file=SimpleUploadedFile(
            'sensitive-name.txt', b'private', content_type='text/plain',
        ),
        original_name='sensitive-name.txt',
        mime_type='text/plain',
        size=7,
        kind=Attachment.KIND_DOCUMENT,
    )
    attachment_id = attachment.pk
    attachment_path = attachment.file.path
    storage = attachment.file.storage

    with mock.patch.object(storage, 'delete', side_effect=OSError('private path')):
        with django_capture_on_commit_callbacks(execute=True):
            attachment.delete()

    pending = PendingFileDeletion.objects.get()
    assert not Attachment.objects.filter(pk=attachment_id).exists()
    assert pending.attempts == 1
    assert pending.last_attempt_at is not None
    assert Path(attachment_path).exists()
    messages = '\n'.join(record.getMessage() for record in caplog.records)
    assert messages == 'event=attachment_file_delete_failed'
    assert 'sensitive-name.txt' not in messages
    assert attachment_path not in messages

    output = StringIO()
    call_command('cleanup_attachments', stdout=output)

    assert not PendingFileDeletion.objects.exists()
    assert not Path(attachment_path).exists()
    assert '1 pending attachment files retried (0 failed)' in output.getvalue()


@pytest.mark.django_db
def test_pending_file_retries_are_bounded_and_dry_run_is_safe(settings):
    settings.ATTACHMENT_FILE_DELETION_BATCH_SIZE = 1
    names = []
    for _index in range(2):
        name = default_storage.save(
            f'outbox-test/{uuid.uuid4().hex}.txt',
            ContentFile(b'queued'),
        )
        names.append(name)
        PendingFileDeletion.objects.create(file_name=name)
    dry_output = StringIO()

    call_command('cleanup_attachments', '--dry-run', stdout=dry_output)

    assert PendingFileDeletion.objects.count() == 2
    assert all(default_storage.exists(name) for name in names)
    assert '2 pending attachment file deletions (batch limit 1)' in dry_output.getvalue()

    with mock.patch.object(default_storage, 'delete', side_effect=OSError('private path')):
        call_command('cleanup_attachments', stdout=StringIO())
    assert PendingFileDeletion.objects.count() == 2
    assert PendingFileDeletion.objects.filter(last_attempt_at__isnull=False).count() == 1

    # A failed oldest entry must rotate behind work that has not been tried,
    # otherwise a full batch of permanent failures can starve the queue.
    call_command('cleanup_attachments', stdout=StringIO())
    assert PendingFileDeletion.objects.count() == 1
    assert sum(default_storage.exists(name) for name in names) == 1

    call_command('cleanup_attachments', stdout=StringIO())
    assert not PendingFileDeletion.objects.exists()
    assert not any(default_storage.exists(name) for name in names)
