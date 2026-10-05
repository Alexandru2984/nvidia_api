import json
from io import StringIO

import pytest
from django.contrib import admin
from django.contrib.admin.models import ADDITION, CHANGE, LogEntry
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.test import RequestFactory

from chat.admin_audit import PrivacyAuditAdminMixin, audit_event_is_valid
from chat.models import AdminAuditEvent, Conversation

pytestmark = pytest.mark.django_db


def _log_change(user, obj, message=None):
    return LogEntry.objects.log_actions(
        user_id=user.pk,
        queryset=[obj],
        action_flag=CHANGE,
        change_message=message or [{'changed': {'fields': ['Title']}}],
        single_object=True,
    )


def test_admin_log_is_sanitized_mirrored_and_security_logged(user, convo, caplog):
    convo.title = 'private customer conversation title'
    convo.save(update_fields=['title'])
    caplog.set_level('WARNING', logger='security')

    entry = _log_change(user, convo, [
        {'changed': {'fields': ['Title', 'System prompt']}},
        {'added': {'name': 'private relation', 'object': 'secret value'}},
    ])

    assert entry.object_repr == f'chat.conversation#{convo.pk}'
    assert 'private' not in entry.object_repr
    assert 'secret' not in entry.change_message
    assert json.loads(entry.change_message) == [
        {'changed': {'fields': ['Title', 'System prompt']}}, {'added': {}},
    ]

    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)
    assert event.actor_user_id == user.pk
    assert event.action == 'change'
    assert event.model_label == 'chat.conversation'
    assert event.object_ref == str(convo.pk)
    assert event.changed_fields == ['Title', 'System prompt']
    assert audit_event_is_valid(event)
    combined_logs = '\n'.join(record.getMessage() for record in caplog.records)
    assert 'event=admin_change' in combined_logs
    assert 'private customer' not in combined_logs
    assert 'secret value' not in combined_logs


def test_nonnumeric_object_identifier_is_hmac_referenced(user):
    content_type = ContentType.objects.get_for_model(user)
    entry = LogEntry.objects.create(
        user=user,
        content_type=content_type,
        object_id='personal-address@example.com',
        object_repr='personal-address@example.com',
        action_flag=ADDITION,
        change_message=[{'added': {'name': 'User', 'object': 'personal-address@example.com'}}],
    )
    assert 'personal-address' not in entry.object_repr
    assert 'personal-address' not in entry.change_message
    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)
    assert event.object_ref.startswith('ref:')
    assert 'personal-address' not in event.object_ref


def test_bulk_deletion_path_creates_one_audit_event_per_object(user):
    first = Conversation.objects.create(user=user, title='first private title', model_id='test/model')
    second = Conversation.objects.create(user=user, title='second private title', model_id='test/model')
    model_admin = admin.site._registry[Conversation]
    request = RequestFactory().post('/admin/chat/conversation/')
    request.user = user

    entries = model_admin.log_deletions(request, [first, second])

    assert len(entries) == 2
    assert AdminAuditEvent.objects.filter(admin_log_id__in=[entry.pk for entry in entries]).count() == 2
    assert all('private title' not in entry.object_repr for entry in entries)


def test_audit_survives_actor_deletion(user, convo):
    entry = _log_change(user, convo)
    event_id = AdminAuditEvent.objects.get(admin_log_id=entry.pk).pk

    user.delete()

    assert not LogEntry.objects.filter(pk=entry.pk).exists()
    assert AdminAuditEvent.objects.filter(pk=event_id).exists()


def test_integrity_failure_is_detected_by_maintenance(user, convo, caplog):
    entry = _log_change(user, convo)
    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)
    AdminAuditEvent.objects.filter(pk=event.pk).update(changed_fields=['tampered'])
    caplog.set_level('ERROR', logger='security')

    call_command('cleanup_attachments', '--dry-run', stdout=StringIO())

    assert any('event=admin_audit_integrity_failed' in record.getMessage()
               for record in caplog.records)


def test_every_registered_admin_is_privacy_audited():
    assert admin.site._registry
    assert all(
        isinstance(model_admin, PrivacyAuditAdminMixin)
        for model_admin in admin.site._registry.values()
    )
