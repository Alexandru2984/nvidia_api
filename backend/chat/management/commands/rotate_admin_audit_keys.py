import logging

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from chat.admin_audit import (
    AdminAuditKeyError,
    audit_event_is_valid,
    audit_event_key_id,
    audit_integrity_tag,
)
from chat.models import AdminAuditEvent

security_log = logging.getLogger('security')


class Command(BaseCommand):
    help = 'Verify and re-tag every privileged audit event with the active key.'

    def handle(self, *args, **options):
        active = settings.ADMIN_AUDIT_ACTIVE_KEY_ID
        rotated = 0
        unchanged = 0
        try:
            with transaction.atomic():
                events = AdminAuditEvent.objects.select_for_update().order_by('pk')
                for event in events:
                    if not audit_event_is_valid(event):
                        raise AdminAuditKeyError('invalid stored audit event')
                    if audit_event_key_id(event) == active:
                        unchanged += 1
                        continue
                    event.integrity_tag = audit_integrity_tag(
                        admin_log_id=event.admin_log_id,
                        actor_user_id=event.actor_user_id,
                        action=event.action,
                        model_label=event.model_label,
                        object_ref=event.object_ref,
                        fields=event.changed_fields,
                    )
                    event.save(update_fields=['integrity_tag'])
                    rotated += 1
        except (AdminAuditKeyError, TypeError, ValueError) as exc:
            raise CommandError(
                'Admin-audit key rotation aborted; no events were re-tagged because '
                'integrity validation failed.',
            ) from exc

        security_log.warning(
            'event=admin_audit_keys_rotated active_key_id=%s rotated=%s unchanged=%s',
            active,
            rotated,
            unchanged,
        )
        self.stdout.write(self.style.SUCCESS(
            f'Admin-audit key rotation complete: rotated={rotated} unchanged={unchanged} '
            f'active_key_id={active}.',
        ))
