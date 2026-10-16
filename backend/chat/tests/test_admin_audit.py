import json
from io import StringIO

import pytest
from django.contrib import admin
from django.contrib.admin.models import ADDITION, CHANGE, LogEntry
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import RequestFactory

from chat.admin_audit import (
    PrivacyAuditAdminMixin,
    audit_event_is_valid,
    object_reference,
)
from chat.models import AdminAuditEvent, Conversation, Message

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
    assert event.integrity_tag.startswith('v1$audit-v1$')
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


def test_audit_artifacts_survive_django_signing_key_rotation(user, convo, settings):
    first_reference = object_reference('stable-private-identifier')
    entry = _log_change(user, convo)
    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)

    settings.SECRET_KEY = 'rotated-django-signing-key'
    assert object_reference('stable-private-identifier') == first_reference
    assert audit_event_is_valid(event)


def test_unknown_or_corrupt_audit_key_fails_closed(user, convo):
    entry = _log_change(user, convo)
    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)
    AdminAuditEvent.objects.filter(pk=event.pk).update(
        integrity_tag='v1$missing$' + ('0' * 64),
    )
    event.refresh_from_db()
    assert not audit_event_is_valid(event)


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


def test_key_inventory_and_rotation(user, convo, settings):
    entry = _log_change(user, convo)
    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)
    call_command('audit_admin_audit_keys', '--require-active', stdout=StringIO())

    settings.ADMIN_AUDIT_ACTIVE_KEY_ID = 'audit-v2'
    with pytest.raises(CommandError, match='inactive key'):
        call_command(
            'audit_admin_audit_keys', '--require-active',
            stdout=StringIO(), stderr=StringIO(),
        )
    call_command('rotate_admin_audit_keys', stdout=StringIO())
    event.refresh_from_db()
    assert event.integrity_tag.startswith('v1$audit-v2$')
    assert audit_event_is_valid(event)
    call_command('audit_admin_audit_keys', '--require-active', stdout=StringIO())


def test_rotation_refuses_to_bless_tampered_event(user, convo, settings):
    entry = _log_change(user, convo)
    event = AdminAuditEvent.objects.get(admin_log_id=entry.pk)
    AdminAuditEvent.objects.filter(pk=event.pk).update(changed_fields=['tampered'])
    settings.ADMIN_AUDIT_ACTIVE_KEY_ID = 'audit-v2'

    with pytest.raises(CommandError, match='integrity validation failed'):
        call_command('rotate_admin_audit_keys', stdout=StringIO(), stderr=StringIO())
    event.refresh_from_db()
    assert event.integrity_tag.startswith('v1$audit-v1$')


def test_every_registered_admin_is_privacy_audited():
    assert admin.site._registry
    assert all(
        isinstance(model_admin, PrivacyAuditAdminMixin)
        for model_admin in admin.site._registry.values()
    )


def test_message_admin_cannot_bypass_storage_reservations(user):
    user.is_staff = True
    user.is_superuser = True
    request = RequestFactory().get('/admin/chat/message/')
    request.user = user
    model_admin = admin.site._registry[Message]

    assert model_admin.has_view_permission(request)
    assert not model_admin.has_add_permission(request)
    assert not model_admin.has_change_permission(request)
    assert not model_admin.has_delete_permission(request)
