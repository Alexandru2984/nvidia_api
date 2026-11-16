"""Admission checks for private file objects and upload coordination metadata.

Callers may use these as a coarse preflight. The authoritative create must hold
ChatStorageGate followed by the owner row until capacity is checked and saved.
"""
import logging
import os

from django.conf import settings
from django.core.files.storage import default_storage
from django.db.models import Count, Q, Sum
from rest_framework.response import Response

from .models import Attachment, AttachmentUploadAttempt, PendingFileDeletion


security_log = logging.getLogger('security')


def _blocked(user_id, scope, resource, used, limit):
    security_log.warning(
        'event=attachment_quota_blocked scope=%s resource=%s user_id=%s',
        scope, resource, user_id,
    )
    if scope == 'global':
        # Never expose service-wide usage or other owners' storage to a client.
        response = Response({
            'error': 'Attachment capacity is temporarily unavailable. Try again later.',
            'code': 'attachment_capacity_unavailable',
        }, status=503)
        response['Retry-After'] = '60'
        return response
    errors = {
        'files': ('File quota exceeded. Delete unused files or older chats first.', 'attachment_limit'),
        'bytes': ('Storage quota exceeded. Delete unused files or older chats first.', 'storage_quota_exceeded'),
        'attempts': ('Too many recent upload attempts. Try again after upload history expires.', 'upload_attempt_limit'),
    }
    message, code = errors[resource]
    return Response({'error': message, 'code': code, 'used': used, 'limit': limit}, status=413)


def attachment_quota_response(user_id, incoming_bytes):
    """Check one additional file, including linked and generated attachments."""
    owner = Q(user_id=user_id)
    usage = Attachment.objects.aggregate(
        files=Count('pk'), bytes=Sum('size'),
        owner_files=Count('pk', filter=owner), owner_bytes=Sum('size', filter=owner),
    )
    # A committed row deletion must not make an undeleted storage object free.
    # Read this after live usage: concurrent deletion can overcount safely,
    # rather than miss both sides of the live-row -> outbox transition. The
    # outbox deliberately has no content/owner metadata, so reserve a whole
    # maximum-sized file per entry until physical cleanup succeeds.
    pending_files = PendingFileDeletion.objects.count()
    for scope, resource, used, added, limit in (
        ('user', 'files', usage['owner_files'], 1, settings.MAX_USER_ATTACHMENTS),
        ('user', 'bytes', usage['owner_bytes'] or 0, incoming_bytes, settings.MAX_USER_STORAGE),
        ('global', 'files', usage['files'] + pending_files, 1, settings.MAX_GLOBAL_ATTACHMENTS),
        ('global', 'bytes', (usage['bytes'] or 0) + pending_files * settings.MAX_ATTACHMENT_SIZE,
         incoming_bytes, settings.MAX_GLOBAL_STORAGE),
    ):
        if used + added > limit:
            return _blocked(user_id, scope, resource, used, limit)
    try:
        filesystem = os.statvfs(default_storage.path(''))
        available_bytes = filesystem.f_bavail * filesystem.f_frsize
        if filesystem.f_frsize <= 0:
            raise OSError('invalid storage allocation unit')
        # Round file data to allocation units and allow for attachments/owner/
        # random directories on a first save. This remains an admission guard,
        # not a filesystem project quota against unrelated writers.
        blocks = (incoming_bytes + filesystem.f_frsize - 1) // filesystem.f_frsize + 3
        if available_bytes - blocks * filesystem.f_frsize < settings.ATTACHMENT_MIN_FREE_BYTES:
            return _blocked(user_id, 'global', 'disk_bytes', 0, 0)
        if filesystem.f_favail - 4 < settings.ATTACHMENT_MIN_FREE_INODES:
            return _blocked(user_id, 'global', 'disk_inodes', 0, 0)
    except (OSError, NotImplementedError):
        return _blocked(user_id, 'global', 'storage_state', 0, 0)
    return None


def upload_attempt_quota_response(user_id):
    """Bound every state, including canceled UUID tombstones, until expiry."""
    usage = AttachmentUploadAttempt.objects.aggregate(
        attempts=Count('pk'), owner_attempts=Count('pk', filter=Q(user_id=user_id)),
    )
    if usage['owner_attempts'] >= settings.MAX_USER_UPLOAD_ATTEMPTS:
        return _blocked(user_id, 'user', 'attempts', usage['owner_attempts'], settings.MAX_USER_UPLOAD_ATTEMPTS)
    if usage['attempts'] >= settings.MAX_GLOBAL_UPLOAD_ATTEMPTS:
        return _blocked(user_id, 'global', 'attempts', usage['attempts'], settings.MAX_GLOBAL_UPLOAD_ATTEMPTS)
    return None
