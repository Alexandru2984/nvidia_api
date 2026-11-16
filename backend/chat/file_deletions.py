"""Transactional, retryable deletion of private attachment storage objects."""
import logging
import errno
import os
import re
from contextlib import ExitStack
from functools import partial

from django.core.files.storage import FileSystemStorage, default_storage
from django.db import models, transaction
from django.utils import timezone

from .models import PendingFileDeletion

security_log = logging.getLogger('security')


def _prune_empty_upload_directory(storage, file_name):
    """Reclaim only this local upload's empty random directory, without links.

    Owner/media roots and nonempty directories are never removed. Non-local or
    legacy storage names keep their existing deletion behavior.
    """
    parts = file_name.split('/')
    if (
        not isinstance(storage, FileSystemStorage)
        or len(parts) != 4 or parts[0] != 'attachments'
        or not re.fullmatch(r'[1-9][0-9]*', parts[1])
        or not re.fullmatch(r'[0-9a-f]{16}', parts[2])
        or parts[3] in ('', '.', '..')
    ):
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        with ExitStack() as descriptors:
            parent = os.open(storage.location, flags)
            descriptors.callback(os.close, parent)
            for part in parts[:2]:
                parent = os.open(part, flags, dir_fd=parent)
                descriptors.callback(os.close, parent)
            try:
                os.rmdir(parts[2], dir_fd=parent)
            except OSError as error:
                if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                    raise
    except FileNotFoundError:
        # Repeated cleanup after the file/directory already disappeared is safe.
        pass


def _delete_stored_file(storage, file_name):
    storage.delete(file_name)
    _prune_empty_upload_directory(storage, file_name)


def retry_pending_file_deletion(pending_id, *, storage=None, using='default'):
    """Attempt one queued delete without exposing its storage name in logs."""
    try:
        pending = (
            PendingFileDeletion.objects.using(using)
            .only('pk', 'file_name')
            .filter(pk=pending_id)
            .first()
        )
        if pending is None:
            return True
        _delete_stored_file(storage or default_storage, pending.file_name)
        PendingFileDeletion.objects.using(using).filter(pk=pending_id).delete()
        return True
    except Exception:
        # Keep the outbox row for bounded daily retry. Avoid exception text and
        # tracebacks because storage backends commonly include the filename.
        try:
            PendingFileDeletion.objects.using(using).filter(pk=pending_id).update(
                attempts=models.F('attempts') + 1,
                last_attempt_at=timezone.now(),
            )
        except Exception:
            pass
        security_log.error('event=attachment_file_delete_failed')
        return False


def enqueue_file_deletion(storage, file_name, *, using='default'):
    """Persist intent in the row transaction; touch storage only after commit."""
    pending, _created = PendingFileDeletion.objects.using(using).get_or_create(
        file_name=file_name,
    )
    transaction.on_commit(
        partial(
            retry_pending_file_deletion,
            pending.pk,
            storage=storage,
            using=using,
        ),
        using=using,
        robust=True,
    )


def discard_uncommitted_file(file_field, *, using='default'):
    """Remove storage written by a database transaction that rolled back."""
    if not getattr(file_field, '_committed', False):
        return True
    file_name = getattr(file_field, 'name', '')
    storage = getattr(file_field, 'storage', None)
    if not file_name or storage is None:
        return True
    try:
        _delete_stored_file(storage, file_name)
        return True
    except Exception:
        # The database transaction that owned the Attachment has already rolled
        # back. Persist a fresh cleanup intent when possible; daily maintenance
        # will retry it without requiring the missing Attachment row.
        try:
            PendingFileDeletion.objects.using(using).get_or_create(
                file_name=file_name,
            )
        except Exception:
            pass
        # Never include exception text or the private storage name.
        security_log.error('event=attachment_file_delete_failed')
        return False
