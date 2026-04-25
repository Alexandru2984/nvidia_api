"""Delete Attachments that were uploaded but never linked to a message.

Recommended cron (daily):
    0 3 * * *  cd /home/micu/nvidia/backend && . venv/bin/activate && python manage.py cleanup_attachments
"""
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from chat.models import Attachment


class Command(BaseCommand):
    help = 'Delete orphan Attachments older than ATTACHMENT_TTL_DAYS.'

    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted, but do not delete.')
        parser.add_argument('--days', type=int, default=None, help='Override TTL days.')

    def handle(self, *args, **opts):
        days = opts['days'] if opts['days'] is not None else settings.ATTACHMENT_TTL_DAYS
        cutoff = timezone.now() - timedelta(days=days)
        qs = Attachment.objects.filter(message__isnull=True, created_at__lt=cutoff)
        count = qs.count()
        total_bytes = sum(qs.values_list('size', flat=True))
        if opts['dry_run']:
            self.stdout.write(f'[dry-run] Would delete {count} orphan attachments ({total_bytes / 1024 / 1024:.1f} MB).')
            return
        for att in qs:
            att.delete()
        self.stdout.write(self.style.SUCCESS(f'Deleted {count} orphan attachments ({total_bytes / 1024 / 1024:.1f} MB).'))
