"""Tests for the cleanup_attachments management command."""
from datetime import timedelta
from io import StringIO

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.utils import timezone

from chat.models import Attachment, Conversation, EmailVerification, Message, PasswordReset


def _make_att(user, days_old=0, linked=False):
    f = SimpleUploadedFile('a.txt', b'hi', content_type='text/plain')
    att = Attachment.objects.create(
        user=user, file=f, original_name='a.txt', mime_type='text/plain', size=2, kind='document',
    )
    if days_old:
        Attachment.objects.filter(pk=att.pk).update(created_at=timezone.now() - timedelta(days=days_old))
    if linked:
        c = Conversation.objects.create(user=user, title='c', model_id='meta/llama-3.1-8b-instruct')
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
