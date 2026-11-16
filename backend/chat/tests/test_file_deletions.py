"""Durable attachment-file deletion outbox coverage."""
import uuid
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage, default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command

from chat.file_deletions import discard_uncommitted_file
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


@pytest.mark.django_db
def test_uncommitted_file_delete_failure_enters_private_outbox(caplog):
    caplog.set_level('ERROR', logger='security')
    name = default_storage.save(
        f'rollback-test/{uuid.uuid4().hex}.txt',
        ContentFile(b'private'),
    )
    file_field = mock.Mock(name='file-field')
    file_field._committed = True
    file_field.name = name
    file_field.storage = default_storage

    with mock.patch.object(default_storage, 'delete', side_effect=OSError('private path')):
        assert discard_uncommitted_file(file_field) is False

    assert PendingFileDeletion.objects.filter(file_name=name).exists()
    messages = '\n'.join(record.getMessage() for record in caplog.records)
    assert messages == 'event=attachment_file_delete_failed'
    assert name not in messages


@pytest.mark.django_db
@pytest.mark.parametrize('operation', ['committed', 'rolled_back'])
def test_file_cleanup_reclaims_only_its_empty_random_directory(
    user, django_capture_on_commit_callbacks, operation,
):
    attachment = Attachment(
        user=user, original_name='private.txt', mime_type='text/plain', size=7,
        kind=Attachment.KIND_DOCUMENT,
    )
    attachment.file.save('private.txt', ContentFile(b'private'), save=operation == 'committed')
    path = Path(attachment.file.path)
    owner_dir = path.parent.parent
    other = owner_dir / 'fedcba9876543210'
    other.mkdir(exist_ok=True)
    marker = other / 'keep.txt'
    marker.write_bytes(b'keep')

    if operation == 'committed':
        with django_capture_on_commit_callbacks(execute=True):
            attachment.delete()
    else:
        assert discard_uncommitted_file(attachment.file)

    assert not path.exists()
    assert not path.parent.exists()
    assert marker.read_bytes() == b'keep'
    assert owner_dir.is_dir()
    assert not PendingFileDeletion.objects.exists()


@pytest.mark.parametrize('symlink_level', ['root', 'attachments', 'owner'])
def test_directory_pruning_never_follows_symlinks(tmp_path, symlink_level):
    from chat.file_deletions import _prune_empty_upload_directory

    root = tmp_path / 'media'
    outside = tmp_path / 'outside'
    outside.mkdir()
    random_name = '0123456789abcdef'
    if symlink_level == 'root':
        root.symlink_to(outside, target_is_directory=True)
        leaf = outside / 'attachments' / '1' / random_name
    elif symlink_level == 'attachments':
        root.mkdir()
        (root / 'attachments').symlink_to(outside, target_is_directory=True)
        leaf = outside / '1' / random_name
    else:
        (root / 'attachments').mkdir(parents=True)
        (root / 'attachments' / '1').symlink_to(outside, target_is_directory=True)
        leaf = outside / random_name
    leaf.mkdir(parents=True)
    storage = FileSystemStorage(location=str(root))

    with pytest.raises(OSError):
        _prune_empty_upload_directory(storage, f'attachments/1/{random_name}/gone.txt')

    assert leaf.is_dir()


@pytest.mark.django_db
def test_retry_removes_empty_directory_left_after_file_was_already_deleted(user):
    from chat.file_deletions import retry_pending_file_deletion

    attachment = Attachment(user=user)
    attachment.file.save('private.txt', ContentFile(b'private'), save=False)
    path = Path(attachment.file.path)
    name = attachment.file.name
    path.unlink()
    pending = PendingFileDeletion.objects.create(file_name=name)

    assert retry_pending_file_deletion(pending.pk)
    assert not path.parent.exists()
    assert not PendingFileDeletion.objects.exists()


@pytest.mark.django_db
def test_failed_directory_cleanup_stays_queued_without_private_paths(user, caplog):
    from chat.file_deletions import retry_pending_file_deletion

    attachment = Attachment(user=user)
    attachment.file.save('private.txt', ContentFile(b'private'), save=False)
    path = Path(attachment.file.path)
    pending = PendingFileDeletion.objects.create(file_name=attachment.file.name)
    with mock.patch('chat.file_deletions.os.rmdir', side_effect=PermissionError('private-path-marker')):
        with caplog.at_level('ERROR', logger='security'):
            assert not retry_pending_file_deletion(pending.pk)

    assert not path.exists()
    assert path.parent.is_dir()
    assert PendingFileDeletion.objects.filter(pk=pending.pk).exists()
    assert 'private-path-marker' not in caplog.text
    assert retry_pending_file_deletion(pending.pk)
    assert not path.parent.exists()
    assert not PendingFileDeletion.objects.exists()


def test_directory_cleanup_preserves_nonempty_upload_directory(tmp_path):
    from chat.file_deletions import _prune_empty_upload_directory

    storage = FileSystemStorage(location=str(tmp_path))
    leaf = tmp_path / 'attachments' / '1' / '0123456789abcdef'
    leaf.mkdir(parents=True)
    marker = leaf / 'keep.txt'
    marker.write_bytes(b'keep')

    _prune_empty_upload_directory(storage, 'attachments/1/0123456789abcdef/gone.txt')

    assert marker.read_bytes() == b'keep'
