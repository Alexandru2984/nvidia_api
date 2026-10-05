"""Daily cleanup: orphan attachments, expired OTPs, and invitation audit rows.

Scheduled in production by `aichat-maintenance.timer`.
"""
from datetime import timedelta

from django.conf import settings
from django.contrib.admin.models import LogEntry
from django.core.management.base import BaseCommand
from django.db import models
from django.utils import timezone

from chat.admin_audit import audit_event_is_valid, security_log
from chat.models import (
    AdminAuditEvent,
    Attachment,
    EmailVerification,
    PasswordReset,
    RegistrationInvite,
)


class Command(BaseCommand):
    help = 'Delete expired temporary uploads, authentication codes, and invitation audit rows.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted, but do not delete.')
        parser.add_argument('--days', type=int, default=None, help='Override attachment TTL days.')

    def handle(self, *args, **opts):
        days = opts['days'] if opts['days'] is not None else settings.ATTACHMENT_TTL_DAYS
        cutoff = timezone.now() - timedelta(days=days)
        dry = opts['dry_run']

        att_qs = Attachment.objects.filter(message__isnull=True, created_at__lt=cutoff)
        att_count = att_qs.count()
        att_bytes = sum(att_qs.values_list('size', flat=True))

        # OTPs expire on their own `expires_at`; once past that they're useless
        # and just leak metadata (which emails recently registered, etc).
        now = timezone.now()
        ev_qs = EmailVerification.objects.filter(expires_at__lt=now)
        pr_qs = PasswordReset.objects.filter(expires_at__lt=now)
        invite_audit_cutoff = now - timedelta(days=settings.REGISTRATION_INVITE_AUDIT_DAYS)
        invite_qs = RegistrationInvite.objects.filter(
            models.Q(used_at__isnull=True, expires_at__lt=now)
            | models.Q(used_at__lt=invite_audit_cutoff)
        )
        admin_audit_cutoff = now - timedelta(days=settings.ADMIN_AUDIT_RETENTION_DAYS)
        admin_audit_qs = AdminAuditEvent.objects.filter(occurred_at__lt=admin_audit_cutoff)
        admin_log_qs = LogEntry.objects.filter(action_time__lt=admin_audit_cutoff)
        ev_count = ev_qs.count()
        pr_count = pr_qs.count()
        invite_count = invite_qs.count()
        admin_audit_count = admin_audit_qs.count()
        admin_log_count = admin_log_qs.count()

        invalid_audits = sum(
            not audit_event_is_valid(event)
            for event in AdminAuditEvent.objects.all().iterator(chunk_size=200)
        )
        missing_audits = LogEntry.objects.exclude(
            pk__in=AdminAuditEvent.objects.values('admin_log_id'),
        ).count()
        if invalid_audits or missing_audits:
            security_log.error(
                'event=admin_audit_integrity_failed invalid_count=%s missing_count=%s',
                invalid_audits,
                missing_audits,
            )

        if dry:
            self.stdout.write('[dry-run] Would delete:')
            self.stdout.write(f'  - {att_count} orphan attachments ({att_bytes / 1024 / 1024:.1f} MB)')
            self.stdout.write(f'  - {ev_count} expired email verifications')
            self.stdout.write(f'  - {pr_count} expired password resets')
            self.stdout.write(f'  - {invite_count} expired invitation audit rows')
            self.stdout.write(
                f'  - {admin_audit_count} expired admin audit events and '
                f'{admin_log_count} admin log entries'
            )
            self.stdout.write(
                f'  - audit integrity: {invalid_audits} invalid, {missing_audits} missing'
            )
            return

        for att in att_qs:
            att.delete()
        ev_qs.delete()
        pr_qs.delete()
        invite_qs.delete()
        admin_audit_qs.delete()
        admin_log_qs.delete()

        self.stdout.write(self.style.SUCCESS(
            f'Deleted {att_count} orphan attachments ({att_bytes / 1024 / 1024:.1f} MB), '
            f'{ev_count} expired email verifications, {pr_count} expired password resets, '
            f'{invite_count} expired invitation audit rows, {admin_audit_count} expired admin '
            f'audit events, {admin_log_count} expired admin log entries.'
        ))
