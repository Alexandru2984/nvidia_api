"""Privacy-safe, tamper-evident auditing for privileged Django admin changes."""
import base64
import binascii
import hashlib
import hmac
import json
import logging
import re

from django.conf import settings
from django.contrib.admin.models import ADDITION, CHANGE, DELETION, LogEntry
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from .models import AdminAuditEvent

security_log = logging.getLogger('security')
ACTION_NAMES = {ADDITION: 'add', CHANGE: 'change', DELETION: 'delete'}
SAFE_FIELD_RE = re.compile(r'[^A-Za-z0-9_. -]+')
KEY_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,32}$')
INTEGRITY_DIGEST_RE = re.compile(r'^[0-9a-f]{64}$')
ENVELOPE_VERSION = 'v1'


class AdminAuditKeyError(ValueError):
    """An admin-audit artifact cannot be verified with configured keys."""


def _root_key(key_id):
    encoded = settings.ADMIN_AUDIT_KEYS.get(key_id)
    if not isinstance(encoded, str):
        raise AdminAuditKeyError('unknown admin-audit key')
    try:
        decoded = base64.b64decode(encoded.encode('ascii'), altchars=b'-_', validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise AdminAuditKeyError('invalid configured admin-audit key') from exc
    if len(decoded) != 32:
        raise AdminAuditKeyError('invalid configured admin-audit key length')
    return decoded


def _derived_key(key_id, purpose):
    return hmac.new(_root_key(key_id), purpose, hashlib.sha256).digest()


def _active_key_id():
    key_id = settings.ADMIN_AUDIT_ACTIVE_KEY_ID
    if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
        raise AdminAuditKeyError('invalid active admin-audit key identifier')
    _root_key(key_id)
    return key_id


def _parse_integrity_tag(stored):
    if not isinstance(stored, str) or not stored:
        raise AdminAuditKeyError('empty admin-audit integrity tag')
    if '$' not in stored:
        if not INTEGRITY_DIGEST_RE.fullmatch(stored):
            raise AdminAuditKeyError('invalid legacy admin-audit tag')
        return None, stored
    parts = stored.split('$', 2)
    if (
        len(parts) != 3
        or parts[0] != ENVELOPE_VERSION
        or not KEY_ID_RE.fullmatch(parts[1])
        or not INTEGRITY_DIGEST_RE.fullmatch(parts[2])
    ):
        raise AdminAuditKeyError('invalid admin-audit tag envelope')
    _root_key(parts[1])
    return parts[1], parts[2]


def _safe_field_name(value):
    return SAFE_FIELD_RE.sub('', str(value))[:64].strip()


def sanitize_change_message(raw_message):
    """Keep only action types and field labels from Django's JSON message."""
    try:
        message = json.loads(raw_message) if isinstance(raw_message, str) else raw_message
    except (TypeError, ValueError, json.JSONDecodeError):
        message = []
    if not isinstance(message, list):
        message = []

    sanitized = []
    for item in message[:50]:
        if not isinstance(item, dict):
            continue
        if 'changed' in item:
            detail = item.get('changed') or {}
            fields = detail.get('fields', []) if isinstance(detail, dict) else []
            safe_fields = [name for field in fields[:50] if (name := _safe_field_name(field))]
            sanitized.append({'changed': {'fields': safe_fields}})
        elif 'added' in item:
            sanitized.append({'added': {}})
        elif 'deleted' in item:
            sanitized.append({'deleted': {}})
    return json.dumps(sanitized, separators=(',', ':'))


def changed_fields_from_message(message):
    try:
        entries = json.loads(message)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    fields = []
    for entry in entries if isinstance(entries, list) else []:
        detail = entry.get('changed') if isinstance(entry, dict) else None
        if not isinstance(detail, dict):
            continue
        for field in detail.get('fields', []):
            safe = _safe_field_name(field)
            if safe and safe not in fields:
                fields.append(safe)
    return fields[:50]


def model_label_for(entry):
    content_type = entry.content_type
    return f'{content_type.app_label}.{content_type.model}' if content_type else 'unknown'


def object_reference(object_id):
    raw = str(object_id or '')
    if re.fullmatch(r'[0-9]{1,20}', raw):
        return raw
    digest = hmac.new(
        _derived_key(_active_key_id(), b'aichat:admin-audit:object-reference:v1'),
        raw.encode('utf-8'),
        hashlib.sha256,
    ).hexdigest()[:20]
    return f'ref:{digest}'


def _audit_payload(*, admin_log_id, actor_user_id, action, model_label, object_ref, fields):
    return json.dumps({
        'action': action,
        'actor_user_id': actor_user_id,
        'admin_log_id': admin_log_id,
        'fields': fields,
        'model_label': model_label,
        'object_ref': object_ref,
    }, sort_keys=True, separators=(',', ':')).encode()


def audit_integrity_tag(
    *, admin_log_id, actor_user_id, action, model_label, object_ref, fields, key_id=None,
):
    key_id = key_id or _active_key_id()
    payload = _audit_payload(
        admin_log_id=admin_log_id,
        actor_user_id=actor_user_id,
        action=action,
        model_label=model_label,
        object_ref=object_ref,
        fields=fields,
    )
    digest = hmac.new(
        _derived_key(key_id, b'aichat:admin-audit:integrity:v1'),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return f'{ENVELOPE_VERSION}${key_id}${digest}'


def _legacy_audit_integrity_tag(
    *, admin_log_id, actor_user_id, action, model_label, object_ref, fields,
):
    payload = _audit_payload(
        admin_log_id=admin_log_id,
        actor_user_id=actor_user_id,
        action=action,
        model_label=model_label,
        object_ref=object_ref,
        fields=fields,
    )
    return hmac.new(
        settings.SECRET_KEY.encode('utf-8'),
        b'admin-audit-v1:' + payload,
        hashlib.sha256,
    ).hexdigest()


def audit_event_key_id(event):
    key_id, _ = _parse_integrity_tag(event.integrity_tag)
    return key_id


def audit_event_is_valid(event):
    values = {
        'admin_log_id': event.admin_log_id,
        'actor_user_id': event.actor_user_id,
        'action': event.action,
        'model_label': event.model_label,
        'object_ref': event.object_ref,
        'fields': event.changed_fields,
    }
    try:
        key_id, digest = _parse_integrity_tag(event.integrity_tag)
        if key_id is None:
            if not settings.ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED:
                return False
            expected = _legacy_audit_integrity_tag(**values)
        else:
            expected = audit_integrity_tag(**values, key_id=key_id).split('$', 2)[2]
        return hmac.compare_digest(digest, expected)
    except (AdminAuditKeyError, TypeError, ValueError):
        return False


@receiver(pre_save, sender=LogEntry, dispatch_uid='chat_sanitize_admin_log_entry')
def sanitize_admin_log_entry(sender, instance, **kwargs):
    model_label = model_label_for(instance)
    reference = object_reference(instance.object_id)
    instance.object_repr = f'{model_label}#{reference}'[:200]
    instance.change_message = sanitize_change_message(instance.change_message)


@receiver(post_save, sender=LogEntry, dispatch_uid='chat_mirror_admin_log_entry')
def mirror_admin_log_entry(sender, instance, created, **kwargs):
    if not created:
        return
    action = ACTION_NAMES.get(instance.action_flag, 'unknown')
    model_label = model_label_for(instance)
    reference = object_reference(instance.object_id)
    fields = changed_fields_from_message(instance.change_message)
    event = AdminAuditEvent.objects.create(
        admin_log_id=instance.pk,
        actor_user_id=instance.user_id,
        action=action,
        model_label=model_label,
        object_ref=reference,
        changed_fields=fields,
        integrity_tag=audit_integrity_tag(
            admin_log_id=instance.pk,
            actor_user_id=instance.user_id,
            action=action,
            model_label=model_label,
            object_ref=reference,
            fields=fields,
        ),
    )
    security_log.warning(
        'event=admin_change action=%s user_id=%s model=%s object_ref=%s fields=%s audit_id=%s',
        action,
        instance.user_id,
        model_label,
        reference,
        ','.join(fields) if fields else '-',
        event.pk,
    )


class PrivacyAuditAdminMixin:
    """Marker and bulk-delete adapter for complete admin LogEntry coverage."""

    def log_deletions(self, request, queryset):
        # Django bulk-creates deletion LogEntry rows, bypassing pre/post-save
        # signals. Persist each tiny audit row separately so it is sanitized and
        # mirrored before the target objects disappear.
        entries = []
        for obj in queryset:
            entries.extend(super().log_deletions(request, [obj]))
        return entries
