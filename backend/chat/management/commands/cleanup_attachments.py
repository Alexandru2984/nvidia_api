"""Daily cleanup: orphan attachments, expired OTPs, and invitation audit rows.

Scheduled in production by `aichat-maintenance.timer`.
"""
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import models
from django.utils import timezone

from chat.models import Attachment, EmailVerification, PasswordReset, RegistrationInvite


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
        ev_count = ev_qs.count()
        pr_count = pr_qs.count()
        invite_count = invite_qs.count()

        if dry:
            self.stdout.write('[dry-run] Would delete:')
            self.stdout.write(f'  - {att_count} orphan attachments ({att_bytes / 1024 / 1024:.1f} MB)')
            self.stdout.write(f'  - {ev_count} expired email verifications')
            self.stdout.write(f'  - {pr_count} expired password resets')
            self.stdout.write(f'  - {invite_count} expired invitation audit rows')
            return

        for att in att_qs:
            att.delete()
        ev_qs.delete()
        pr_qs.delete()
        invite_qs.delete()

        self.stdout.write(self.style.SUCCESS(
            f'Deleted {att_count} orphan attachments ({att_bytes / 1024 / 1024:.1f} MB), '
            f'{ev_count} expired email verifications, {pr_count} expired password resets, '
            f'{invite_count} expired invitation audit rows.'
        ))
