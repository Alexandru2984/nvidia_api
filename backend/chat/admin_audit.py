"""Privacy-safe, tamper-evident auditing for privileged Django admin changes."""
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
        settings.SECRET_KEY.encode(), f'admin-object-v1:{raw}'.encode(), hashlib.sha256,
    ).hexdigest()[:20]
    return f'ref:{digest}'


def audit_integrity_tag(*, admin_log_id, actor_user_id, action, model_label, object_ref, fields):
    payload = json.dumps({
        'action': action,
        'actor_user_id': actor_user_id,
        'admin_log_id': admin_log_id,
        'fields': fields,
        'model_label': model_label,
        'object_ref': object_ref,
    }, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(
        settings.SECRET_KEY.encode(), b'admin-audit-v1:' + payload, hashlib.sha256,
    ).hexdigest()


def audit_event_is_valid(event):
    expected = audit_integrity_tag(
        admin_log_id=event.admin_log_id,
        actor_user_id=event.actor_user_id,
        action=event.action,
        model_label=event.model_label,
        object_ref=event.object_ref,
        fields=event.changed_fields,
    )
    return hmac.compare_digest(event.integrity_tag, expected)


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
