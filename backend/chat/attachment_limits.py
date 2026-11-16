"""Admission checks for private file objects and upload coordination metadata.

Callers may use these as a coarse preflight. The authoritative create must hold
ChatStorageGate followed by the owner row until capacity is checked and saved.
"""
import logging

from django.conf import settings
from django.db.models import Count, Q, Sum
from rest_framework.response import Response

from .models import Attachment, AttachmentUploadAttempt


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
    for scope, resource, used, added, limit in (
        ('user', 'files', usage['owner_files'], 1, settings.MAX_USER_ATTACHMENTS),
        ('user', 'bytes', usage['owner_bytes'] or 0, incoming_bytes, settings.MAX_USER_STORAGE),
        ('global', 'files', usage['files'], 1, settings.MAX_GLOBAL_ATTACHMENTS),
        ('global', 'bytes', usage['bytes'] or 0, incoming_bytes, settings.MAX_GLOBAL_STORAGE),
    ):
        if used + added > limit:
            return _blocked(user_id, scope, resource, used, limit)
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
