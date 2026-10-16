"""Tests for the cleanup_attachments management command."""
from datetime import timedelta
from io import StringIO

import pytest
from django.conf import settings
from django.contrib.sessions.models import Session
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.utils import timezone

from chat.models import (
    AdminAuditEvent,
    Attachment,
    AttachmentUploadAttempt,
    AuthenticatedSession,
    Conversation,
    ConversationGenerationLease,
    EmailVerification,
    GenerationRequest,
    Message,
    PasswordReset,
    RegistrationInvite,
)
from chat.models_catalog import DEFAULT_MODEL_ID


def _make_att(user, days_old=0, linked=False):
    f = SimpleUploadedFile('a.txt', b'hi', content_type='text/plain')
    att = Attachment.objects.create(
        user=user, file=f, original_name='a.txt', mime_type='text/plain', size=2, kind='document',
    )
    if days_old:
        Attachment.objects.filter(pk=att.pk).update(created_at=timezone.now() - timedelta(days=days_old))
    if linked:
        c = Conversation.objects.create(user=user, title='c', model_id=DEFAULT_MODEL_ID)
        m = Message.objects.create(conversation=c, role='user', content='x')
        att.message = m
        att.save()
    return att


@pytest.mark.django_db
class TestCleanupAttachments:
    def test_deletes_orphan_older_than_ttl(self, user):
        old = _make_att(user, days_old=settings.ATTACHMENT_TTL_DAYS + 1)
        new = _make_att(user, days_old=0)
        linked_old = _make_att(user, days_old=settings.ATTACHMENT_TTL_DAYS + 1, linked=True)

        call_command('cleanup_attachments', stdout=StringIO())

        assert not Attachment.objects.filter(pk=old.pk).exists()
        assert Attachment.objects.filter(pk=new.pk).exists()
        assert Attachment.objects.filter(pk=linked_old.pk).exists()  # linked → keep

    def test_dry_run_does_not_delete(self, user):
        _make_att(user, days_old=settings.ATTACHMENT_TTL_DAYS + 1)
        out = StringIO()
        call_command('cleanup_attachments', '--dry-run', stdout=out)
        assert 'dry-run' in out.getvalue()
        assert Attachment.objects.count() == 1

    def test_deletes_expired_otps(self, user, other_user):
        now = timezone.now()
        EmailVerification.objects.create(
            user=user, code_hash='x', sent_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
        EmailVerification.objects.create(
            user=other_user, code_hash='y', sent_at=now,
            expires_at=now + timedelta(hours=1),
        )
        PasswordReset.objects.create(
            user=user, code_hash='z', sent_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )

        call_command('cleanup_attachments', stdout=StringIO())

        assert EmailVerification.objects.count() == 1  # the still-valid one survives
        assert EmailVerification.objects.first().user == other_user
        assert PasswordReset.objects.count() == 0

    def test_dry_run_reports_counts(self, user):
        _make_att(user, days_old=settings.ATTACHMENT_TTL_DAYS + 1)
        EmailVerification.objects.create(
            user=user, code_hash='x',
            sent_at=timezone.now() - timedelta(hours=2),
            expires_at=timezone.now() - timedelta(hours=1),
        )
        out = StringIO()
        call_command('cleanup_attachments', '--dry-run', stdout=out)
        text = out.getvalue()
        assert '1 orphan attachments' in text
        assert '1 expired email verifications' in text

    def test_custom_days_override(self, user):
        # Attachment is only 5 days old. Default TTL would keep it; --days=1 should delete.
        _make_att(user, days_old=5)
        call_command('cleanup_attachments', '--days=1', stdout=StringIO())
        assert Attachment.objects.count() == 0

    def test_removes_expired_upload_attempts(self, user, settings):
        settings.ATTACHMENT_UPLOAD_ATTEMPT_TTL_HOURS = 24
        old = AttachmentUploadAttempt.objects.create(
            id='00000000-0000-4000-8000-000000000001',
            user=user,
        )
        recent = AttachmentUploadAttempt.objects.create(
            id='00000000-0000-4000-8000-000000000002',
            user=user,
        )
        AttachmentUploadAttempt.objects.filter(pk=old.pk).update(
            updated_at=timezone.now() - timedelta(hours=25),
        )

        call_command('cleanup_attachments', stdout=StringIO())

        assert not AttachmentUploadAttempt.objects.filter(pk=old.pk).exists()
        assert AttachmentUploadAttempt.objects.filter(pk=recent.pk).exists()

    def test_removes_only_expired_generation_leases(self, user):
        now = timezone.now()
        expired_convo = Conversation.objects.create(
            user=user,
            title='expired',
            model_id=DEFAULT_MODEL_ID,
        )
        active_convo = Conversation.objects.create(
            user=user,
            title='active',
            model_id=DEFAULT_MODEL_ID,
        )
        ConversationGenerationLease.objects.create(
            conversation=expired_convo,
            token='00000000-0000-4000-8000-000000000001',
            expires_at=now - timedelta(seconds=1),
        )
        active = ConversationGenerationLease.objects.create(
            conversation=active_convo,
            token='00000000-0000-4000-8000-000000000002',
            expires_at=now + timedelta(minutes=5),
        )

        call_command('cleanup_attachments', stdout=StringIO())

        assert list(
            ConversationGenerationLease.objects.values_list('pk', flat=True)
        ) == [active.pk]

    def test_interrupts_stale_generation_and_expires_only_old_terminal_records(
        self,
        user,
        settings,
    ):
        settings.GENERATION_REQUEST_RETENTION_DAYS = 7
        now = timezone.now()
        convo = Conversation.objects.create(
            user=user,
            title='durable request cleanup',
            model_id=DEFAULT_MODEL_ID,
        )
        pending_message = Message.objects.create(
            conversation=convo,
            role='user',
            content='pending',
        )
        pending_attachment = _make_att(user)
        pending_attachment.message = pending_message
        pending_attachment.save(update_fields=['message'])
        stale = GenerationRequest.objects.create(
            user=user,
            conversation=convo,
            idempotency_key='00000000-0000-4000-8000-000000000010',
            operation=GenerationRequest.OPERATION_SEND,
            request_fingerprint='a' * 64,
            user_message=pending_message,
        )
        ConversationGenerationLease.objects.create(
            conversation=convo,
            token='00000000-0000-4000-8000-000000000011',
            generation_request=stale,
            expires_at=now - timedelta(seconds=1),
        )
        old_terminal = GenerationRequest.objects.create(
            user=user,
            conversation=convo,
            idempotency_key='00000000-0000-4000-8000-000000000012',
            operation=GenerationRequest.OPERATION_SEND,
            request_fingerprint='b' * 64,
            state=GenerationRequest.STATE_FAILED,
            completed_at=now - timedelta(days=8),
        )
        recent_terminal = GenerationRequest.objects.create(
            user=user,
            conversation=convo,
            idempotency_key='00000000-0000-4000-8000-000000000013',
            operation=GenerationRequest.OPERATION_SEND,
            request_fingerprint='c' * 64,
            state=GenerationRequest.STATE_FAILED,
            completed_at=now,
        )
        GenerationRequest.objects.filter(pk=old_terminal.pk).update(
            updated_at=now - timedelta(days=8),
        )

        call_command('cleanup_attachments', stdout=StringIO())

        stale.refresh_from_db()
        pending_attachment.refresh_from_db()
        assert stale.state == GenerationRequest.STATE_INTERRUPTED
        assert stale.outcome_code == 'lease_expired'
        assert not Message.objects.filter(pk=pending_message.pk).exists()
        assert pending_attachment.message_id is None
        assert not ConversationGenerationLease.objects.filter(conversation=convo).exists()
        assert not GenerationRequest.objects.filter(pk=old_terminal.pk).exists()
        assert GenerationRequest.objects.filter(pk=recent_terminal.pk).exists()

    def test_removes_only_expired_database_sessions(self, user):
        now = timezone.now()
        Session.objects.create(
            session_key='a' * 40,
            session_data='',
            expire_date=now - timedelta(seconds=1),
        )
        active = Session.objects.create(
            session_key='b' * 40,
            session_data='',
            expire_date=now + timedelta(minutes=5),
        )
        absolute_expired = Session.objects.create(
            session_key='c' * 40,
            session_data='',
            expire_date=now + timedelta(days=5),
        )
        AuthenticatedSession.objects.create(
            session=absolute_expired,
            user=user,
            handle='d' * 64,
            login_at=now - timedelta(days=31),
            absolute_expires_at=now - timedelta(days=1),
        )

        output = StringIO()
        call_command('cleanup_attachments', stdout=output)

        assert list(Session.objects.values_list('pk', flat=True)) == [active.pk]
        assert not AuthenticatedSession.objects.exists()
        assert '2 expired sessions' in output.getvalue()

    def test_removes_expired_and_old_used_invitation_audit_rows(self, user, settings):
        settings.REGISTRATION_INVITE_AUDIT_DAYS = 90
        now = timezone.now()
        RegistrationInvite.objects.create(
            code_hash='a' * 64,
            expires_at=now - timedelta(seconds=1),
        )
        RegistrationInvite.objects.create(
            code_hash='b' * 64,
            expires_at=now - timedelta(days=100),
            used_at=now - timedelta(days=91),
            used_by=user,
        )
        keep = RegistrationInvite.objects.create(
            code_hash='c' * 64,
            expires_at=now + timedelta(days=1),
        )

        call_command('cleanup_attachments', stdout=StringIO())

        assert list(RegistrationInvite.objects.values_list('pk', flat=True)) == [keep.pk]

    def test_dry_run_reports_clean_admin_audit_integrity(self, user, convo):
        from django.contrib.admin.models import CHANGE, LogEntry

        LogEntry.objects.log_actions(
            user_id=user.pk,
            queryset=[convo],
            action_flag=CHANGE,
            change_message=[{'changed': {'fields': ['Title']}}],
            single_object=True,
        )
        output = StringIO()

        call_command('cleanup_attachments', '--dry-run', stdout=output)

        assert 'audit integrity: 0 invalid, 0 missing' in output.getvalue()
        assert AdminAuditEvent.objects.count() == 1
