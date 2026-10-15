from collections import Counter

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from chat.admin_audit import (
    AdminAuditKeyError,
    audit_event_is_valid,
    audit_event_key_id,
)
from chat.models import AdminAuditEvent


class Command(BaseCommand):
    help = 'Validate every privileged audit event and report its key dependency.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--require-active',
            action='store_true',
            help='Fail if any valid event is not tagged by the active key.',
        )

    def handle(self, *args, **options):
        dependencies = Counter()
        invalid = 0
        for event in AdminAuditEvent.objects.all().iterator(chunk_size=200):
            if not audit_event_is_valid(event):
                invalid += 1
                continue
            try:
                dependencies[audit_event_key_id(event) or 'legacy'] += 1
            except (AdminAuditKeyError, TypeError, ValueError):
                invalid += 1

        total = sum(dependencies.values()) + invalid
        self.stdout.write(
            f'Admin-audit key inventory: rows={total} '
            f'keys={dict(sorted(dependencies.items()))} invalid={invalid}'
        )
        if invalid:
            raise CommandError('Privileged audit events failed integrity validation.')
        if options['require_active'] and set(dependencies).difference({
            settings.ADMIN_AUDIT_ACTIVE_KEY_ID,
        }):
            raise CommandError('Privileged audit events still depend on an inactive key.')
        self.stdout.write(self.style.SUCCESS(
            'Admin-audit key inventory passed; '
            f'active_key_id={settings.ADMIN_AUDIT_ACTIVE_KEY_ID}',
        ))
