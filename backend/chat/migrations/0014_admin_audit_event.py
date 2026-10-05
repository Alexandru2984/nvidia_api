import hashlib
import hmac
import json
import re

from django.conf import settings
from django.db import migrations, models


def _safe_field_name(value):
    return re.sub(r'[^A-Za-z0-9_. -]+', '', str(value))[:64].strip()


def _sanitize_message(raw_message):
    try:
        message = json.loads(raw_message) if isinstance(raw_message, str) else raw_message
    except (TypeError, ValueError, json.JSONDecodeError):
        message = []
    if not isinstance(message, list):
        message = []
    sanitized = []
    fields = []
    for item in message[:50]:
        if not isinstance(item, dict):
            continue
        if 'changed' in item:
            detail = item.get('changed') or {}
            raw_fields = detail.get('fields', []) if isinstance(detail, dict) else []
            safe_fields = [name for field in raw_fields[:50] if (name := _safe_field_name(field))]
            sanitized.append({'changed': {'fields': safe_fields}})
            for field in safe_fields:
                if field not in fields:
                    fields.append(field)
        elif 'added' in item:
            sanitized.append({'added': {}})
        elif 'deleted' in item:
            sanitized.append({'deleted': {}})
    return json.dumps(sanitized, separators=(',', ':')), fields[:50]


def _object_reference(object_id):
    raw = str(object_id or '')
    if re.fullmatch(r'[0-9]{1,20}', raw):
        return raw
    digest = hmac.new(
        settings.SECRET_KEY.encode(), f'admin-object-v1:{raw}'.encode(), hashlib.sha256,
    ).hexdigest()[:20]
    return f'ref:{digest}'


def _integrity_tag(entry_id, user_id, action, model_label, object_ref, fields):
    payload = json.dumps({
        'action': action,
        'actor_user_id': user_id,
        'admin_log_id': entry_id,
        'fields': fields,
        'model_label': model_label,
        'object_ref': object_ref,
    }, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(
        settings.SECRET_KEY.encode(), b'admin-audit-v1:' + payload, hashlib.sha256,
    ).hexdigest()


def sanitize_and_backfill(apps, schema_editor):
    LogEntry = apps.get_model('admin', 'LogEntry')
    AdminAuditEvent = apps.get_model('chat', 'AdminAuditEvent')
    actions = {1: 'add', 2: 'change', 3: 'delete'}
    for entry in LogEntry.objects.select_related('content_type').iterator(chunk_size=200):
        content_type = entry.content_type
        model_label = (
            f'{content_type.app_label}.{content_type.model}' if content_type else 'unknown'
        )
        reference = _object_reference(entry.object_id)
        message, fields = _sanitize_message(entry.change_message)
        LogEntry.objects.filter(pk=entry.pk).update(
            object_repr=f'{model_label}#{reference}'[:200],
            change_message=message,
        )
        action = actions.get(entry.action_flag, 'unknown')
        audit_event = AdminAuditEvent.objects.create(
            admin_log_id=entry.pk,
            actor_user_id=entry.user_id,
            action=action,
            model_label=model_label,
            object_ref=reference,
            changed_fields=fields,
            integrity_tag=_integrity_tag(
                entry.pk, entry.user_id, action, model_label, reference, fields,
            ),
        )
        AdminAuditEvent.objects.filter(pk=audit_event.pk).update(occurred_at=entry.action_time)


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012 - Django migration declaration
        ('admin', '0003_logentry_add_action_flag_choices'),
        ('chat', '0013_registration_invite'),
    ]

    operations = [  # noqa: RUF012 - Django migration declaration
        migrations.CreateModel(
            name='AdminAuditEvent',
            fields=[
                ('id', models.BigAutoField(
                    auto_created=True, primary_key=True, serialize=False, verbose_name='ID',
                )),
                ('occurred_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('admin_log_id', models.PositiveBigIntegerField(unique=True)),
                ('actor_user_id', models.PositiveBigIntegerField(db_index=True)),
                ('action', models.CharField(
                    choices=[('add', 'Add'), ('change', 'Change'), ('delete', 'Delete')],
                    max_length=10,
                )),
                ('model_label', models.CharField(db_index=True, max_length=150)),
                ('object_ref', models.CharField(max_length=64)),
                ('changed_fields', models.JSONField(default=list)),
                ('integrity_tag', models.CharField(max_length=64)),
            ],
            options={'ordering': ['-occurred_at']},
        ),
        migrations.RunPython(sanitize_and_backfill, migrations.RunPython.noop),
    ]
