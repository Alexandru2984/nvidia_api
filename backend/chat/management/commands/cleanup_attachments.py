"""Daily cleanup for expired uploads, auth metadata, audits, and generation leases.

Scheduled in production by `aichat-maintenance.timer`.
"""
from datetime import timedelta

from django.conf import settings
from django.contrib.admin.models import LogEntry
from django.contrib.sessions.models import Session
from django.core.management.base import BaseCommand
from django.db import models, transaction
from django.utils import timezone

from chat.admin_audit import audit_event_is_valid, security_log
from chat.models import (
    AdminAuditEvent,
    Attachment,
    AttachmentUploadAttempt,
    ConversationGenerationLease,
    EmailVerification,
    GenerationRequest,
    Message,
    PasswordReset,
    RegistrationInvite,
)


class Command(BaseCommand):
    help = 'Delete expired uploads, auth metadata, audit rows, and generation leases.'

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
        upload_attempt_cutoff = now - timedelta(
            hours=settings.ATTACHMENT_UPLOAD_ATTEMPT_TTL_HOURS,
        )
        upload_attempt_qs = AttachmentUploadAttempt.objects.filter(
            updated_at__lt=upload_attempt_cutoff,
        )
        generation_lease_qs = ConversationGenerationLease.objects.filter(
            expires_at__lte=now,
        )
        stale_generation_request_qs = GenerationRequest.objects.filter(
            models.Q(lease__isnull=True) | models.Q(lease__expires_at__lte=now),
            state__in=GenerationRequest.ACTIVE_STATES,
        )
        generation_request_cutoff = now - timedelta(
            days=settings.GENERATION_REQUEST_RETENTION_DAYS,
        )
        expired_generation_request_qs = GenerationRequest.objects.filter(
            state__in=GenerationRequest.TERMINAL_STATES,
            updated_at__lt=generation_request_cutoff,
        )
        session_qs = Session.objects.filter(
            models.Q(expire_date__lte=now)
            | models.Q(chat_authentication__absolute_expires_at__lte=now)
        ).distinct()
        ev_count = ev_qs.count()
        pr_count = pr_qs.count()
        invite_count = invite_qs.count()
        admin_audit_count = admin_audit_qs.count()
        admin_log_count = admin_log_qs.count()
        upload_attempt_count = upload_attempt_qs.count()
        generation_lease_count = generation_lease_qs.count()
        stale_generation_request_count = stale_generation_request_qs.count()
        expired_generation_request_count = expired_generation_request_qs.count()
        session_count = session_qs.count()

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
            self.stdout.write(f'  - {upload_attempt_count} expired upload attempts')
            self.stdout.write(f'  - {generation_lease_count} expired generation leases')
            self.stdout.write(
                f'  - {stale_generation_request_count} interrupted generation requests'
            )
            self.stdout.write(
                f'  - {expired_generation_request_count} expired generation request records'
            )
            self.stdout.write(f'  - {session_count} expired sessions')
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
        upload_attempt_qs.delete()
        stale_generation_request_ids = list(
            stale_generation_request_qs.values_list('pk', flat=True)
        )
        for generation_request_id in stale_generation_request_ids:
            with transaction.atomic():
                # Match the request path's lease -> request lock order.
                lease = ConversationGenerationLease.objects.select_for_update().filter(
                    generation_request_id=generation_request_id,
                ).first()
                generation_request = GenerationRequest.objects.select_for_update().filter(
                    pk=generation_request_id,
                    state__in=GenerationRequest.ACTIVE_STATES,
                ).first()
                if generation_request is None:
                    continue
                if lease is not None and lease.expires_at > now:
                    continue
                if (
                    generation_request.operation == GenerationRequest.OPERATION_SEND
                    and generation_request.user_message_id is not None
                    and generation_request.assistant_message_id is None
                ):
                    Attachment.objects.filter(
                        message_id=generation_request.user_message_id,
                    ).update(message=None)
                    Message.objects.filter(id=generation_request.user_message_id).delete()
                GenerationRequest.objects.filter(pk=generation_request.pk).update(
                    state=GenerationRequest.STATE_INTERRUPTED,
                    outcome_code='lease_expired',
                    completed_at=now,
                    updated_at=now,
                )
        generation_lease_qs.delete()
        expired_generation_request_qs.delete()
        session_qs.delete()

        self.stdout.write(self.style.SUCCESS(
            f'Deleted {att_count} orphan attachments ({att_bytes / 1024 / 1024:.1f} MB), '
            f'{ev_count} expired email verifications, {pr_count} expired password resets, '
            f'{invite_count} expired invitation audit rows, {admin_audit_count} expired admin '
            f'audit events, {admin_log_count} expired admin log entries, '
            f'{upload_attempt_count} expired upload attempts, '
            f'{generation_lease_count} expired generation leases, '
            f'{stale_generation_request_count} interrupted generation requests, '
            f'{expired_generation_request_count} expired generation request records, '
            f'{session_count} expired sessions.'
        ))
