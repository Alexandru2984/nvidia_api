"""Transactional, retryable deletion of private attachment storage objects."""
import logging
from functools import partial

from django.core.files.storage import default_storage
from django.db import models, transaction
from django.utils import timezone

from .models import PendingFileDeletion

security_log = logging.getLogger('security')


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
        (storage or default_storage).delete(pending.file_name)
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
