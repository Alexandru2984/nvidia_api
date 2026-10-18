"""Daily cleanup for expired data, retention, leases, and due account deletion.

Scheduled in production by `aichat-maintenance.timer`.
"""
from datetime import timedelta

from django.conf import settings
from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.management.base import BaseCommand
from django.db import models, transaction
from django.utils import timezone

from chat.admin_audit import audit_event_is_valid, security_log
from chat.models import (
    AccountDeletionRequest,
    AdminAuditEvent,
    Attachment,
    AttachmentUploadAttempt,
    ChatHistoryRetention,
    ChatStorageGate,
    Conversation,
    ConversationGenerationLease,
    DailyAIUsage,
    EmailVerification,
    GenerationRequest,
    GlobalAIUsage,
    Message,
    PasswordReset,
    RegistrationInvite,
)
from chat.sessions import revoke_user_sessions


class Command(BaseCommand):
    help = (
        'Delete expired uploads/auth metadata/retained chats/audits/leases '
        'and execute due account deletions.'
    )

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
        today = timezone.localdate()
        user_usage_cutoff = today - timedelta(
            days=settings.AI_USER_USAGE_RETENTION_DAYS,
        )
        global_usage_cutoff = today - timedelta(
            days=settings.AI_GLOBAL_USAGE_RETENTION_DAYS,
        )
        expired_user_usage_qs = DailyAIUsage.objects.filter(
            day__lt=user_usage_cutoff,
        )
        expired_global_usage_qs = GlobalAIUsage.objects.filter(
            day__lt=global_usage_cutoff,
        )
        expired_user_usage_count = expired_user_usage_qs.count()
        expired_global_usage_count = expired_global_usage_qs.count()
        usage_delete_batch_size = settings.AI_USAGE_RETENTION_DELETE_BATCH_SIZE
        expired_user_usage_ids = list(
            expired_user_usage_qs.order_by('day', 'id').values_list('pk', flat=True)
            [:usage_delete_batch_size]
        )
        expired_global_usage_ids = list(
            expired_global_usage_qs.order_by('day', 'id').values_list('pk', flat=True)
            [:usage_delete_batch_size]
        )
        due_account_deletion_qs = AccountDeletionRequest.objects.filter(
            execute_after__lte=now,
        )
        due_account_deletion_count = due_account_deletion_qs.count()
        retention_filter = models.Q(pk__isnull=True)
        for retention_days in ChatHistoryRetention.DELETE_DAYS:
            retention_cutoff = now - timedelta(days=retention_days)
            retention_filter |= models.Q(
                user__chat_history_retention__archived_days=retention_days,
                archived_at__lt=retention_cutoff,
                updated_at__lt=retention_cutoff,
            )
        retention_qs = Conversation.objects.filter(
            retention_filter,
            generation_lease__isnull=True,
        )
        retention_count = retention_qs.count()
        retention_message_usage = Message.objects.filter(
            conversation__in=retention_qs,
        ).aggregate(
            count=models.Count('id'),
            bytes=models.Sum('content_bytes'),
        )
        retention_candidates = list(
            retention_qs.order_by('updated_at', 'id').values_list('pk', 'user_id')
            [:settings.CHAT_RETENTION_DELETE_BATCH_SIZE]
        )
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
                f'  - {expired_user_usage_count} expired per-user AI usage rows '
                f'(older than {settings.AI_USER_USAGE_RETENTION_DAYS} days; '
                f'batch limit {usage_delete_batch_size})'
            )
            self.stdout.write(
                f'  - {expired_global_usage_count} expired aggregate AI usage rows '
                f'(older than {settings.AI_GLOBAL_USAGE_RETENTION_DAYS} days; '
                f'batch limit {usage_delete_batch_size})'
            )
            self.stdout.write(
                f'  - {retention_count} retention-eligible archived conversations '
                f'({retention_message_usage["count"] or 0} messages, '
                f'{(retention_message_usage["bytes"] or 0) / 1024 / 1024:.1f} MiB; '
                f'batch limit {settings.CHAT_RETENTION_DELETE_BATCH_SIZE})'
            )
            self.stdout.write(
                f'  - {due_account_deletion_count} due account deletions '
                f'(batch limit {settings.ACCOUNT_DELETION_BATCH_SIZE})'
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
        deleted_user_usage_rows, _ = DailyAIUsage.objects.filter(
            pk__in=expired_user_usage_ids,
        ).delete()
        deleted_global_usage_rows, _ = GlobalAIUsage.objects.filter(
            pk__in=expired_global_usage_ids,
        ).delete()
        if deleted_user_usage_rows or deleted_global_usage_rows:
            security_log.info(
                'event=ai_usage_retention_deleted user_rows=%s global_rows=%s',
                deleted_user_usage_rows,
                deleted_global_usage_rows,
            )

        retained_conversations_deleted = 0
        retained_messages_deleted = 0
        retained_bytes_deleted = 0
        User = get_user_model()
        for conversation_id, user_id in retention_candidates:
            with transaction.atomic():
                # Match generation's global gate -> owner -> conversation order.
                # A newly acquired lease or changed owner policy wins safely.
                ChatStorageGate.objects.select_for_update().get(pk=1)
                locked_user = User.objects.select_for_update().only('pk').filter(
                    pk=user_id,
                ).first()
                if locked_user is None:
                    continue
                retention = ChatHistoryRetention.objects.filter(
                    user_id=user_id,
                ).only('archived_days').first()
                if retention is None or retention.archived_days not in (
                    ChatHistoryRetention.DELETE_DAYS
                ):
                    continue
                retention_cutoff = now - timedelta(days=retention.archived_days)
                conversation = Conversation.objects.select_for_update().filter(
                    pk=conversation_id,
                    user_id=user_id,
                    archived_at__lt=retention_cutoff,
                    updated_at__lt=retention_cutoff,
                ).first()
                if conversation is None:
                    continue
                # Keep the nullable reverse one-to-one out of the locked
                # conversation query. PostgreSQL rejects FOR UPDATE when it
                # applies to the nullable side of the resulting outer join.
                # The global gate above prevents a generation from acquiring
                # a new lease between this check and the delete.
                if ConversationGenerationLease.objects.filter(
                    conversation_id=conversation.pk,
                ).exists():
                    continue
                message_usage = Message.objects.filter(
                    conversation=conversation,
                ).aggregate(
                    count=models.Count('id'),
                    bytes=models.Sum('content_bytes'),
                )
                conversation.delete()
                retained_conversations_deleted += 1
                retained_messages_deleted += message_usage['count'] or 0
                retained_bytes_deleted += message_usage['bytes'] or 0

        if retained_conversations_deleted:
            security_log.info(
                'event=chat_history_retention_deleted conversations=%s messages=%s bytes=%s',
                retained_conversations_deleted,
                retained_messages_deleted,
                retained_bytes_deleted,
            )

        accounts_deleted = 0
        account_sessions_revoked = 0
        # Expired generation leases were removed above. Exclude the remaining
        # active owners before slicing so one long generation cannot consume a
        # deletion batch slot and starve other due accounts.
        active_owner_lease = ConversationGenerationLease.objects.filter(
            conversation__user_id=models.OuterRef('user_id'),
        )
        account_deletion_candidates = list(
            AccountDeletionRequest.objects.filter(execute_after__lte=timezone.now())
            .annotate(has_generation_lease=models.Exists(active_owner_lease))
            .filter(has_generation_lease=False)
            .order_by('execute_after', 'user_id')
            .values_list('user_id', flat=True)[:settings.ACCOUNT_DELETION_BATCH_SIZE]
        )
        for user_id in account_deletion_candidates:
            executed = False
            revoked = 0
            with transaction.atomic():
                # Match generation's global gate -> owner lock order and keep
                # the deletion request recheck inside the irreversible section.
                ChatStorageGate.objects.select_for_update().get(pk=1)
                locked_user = User.objects.select_for_update().filter(pk=user_id).first()
                if locked_user is None:
                    continue
                deletion = AccountDeletionRequest.objects.select_for_update().filter(
                    user_id=user_id,
                    execute_after__lte=timezone.now(),
                ).first()
                if deletion is None:
                    continue
                if ConversationGenerationLease.objects.filter(
                    conversation__user_id=user_id,
                ).exists():
                    continue
                revoked = revoke_user_sessions(locked_user)
                locked_user.delete()
                accounts_deleted += 1
                account_sessions_revoked += revoked
                executed = True
            # Do not emit irreversible-success evidence until the database
            # transaction has actually committed.
            if executed:
                transaction.on_commit(
                    lambda deleted_user_id=user_id, revoked_count=revoked: (
                        security_log.warning(
                            'event=account_deletion_executed '
                            'former_user_id=%s sessions_revoked=%s',
                            deleted_user_id,
                            revoked_count,
                        )
                    ),
                )

        self.stdout.write(self.style.SUCCESS(
            f'Deleted {att_count} orphan attachments ({att_bytes / 1024 / 1024:.1f} MB), '
            f'{ev_count} expired email verifications, {pr_count} expired password resets, '
            f'{invite_count} expired invitation audit rows, {admin_audit_count} expired admin '
            f'audit events, {admin_log_count} expired admin log entries, '
            f'{upload_attempt_count} expired upload attempts, '
            f'{generation_lease_count} expired generation leases, '
            f'{stale_generation_request_count} interrupted generation requests, '
            f'{expired_generation_request_count} expired generation request records, '
            f'{session_count} expired sessions, '
            f'{deleted_user_usage_rows} expired per-user AI usage rows, '
            f'{deleted_global_usage_rows} expired aggregate AI usage rows, '
            f'{retained_conversations_deleted} retained archived conversations '
            f'({retained_messages_deleted} messages, {retained_bytes_deleted} bytes), '
            f'{accounts_deleted} due accounts ({account_sessions_revoked} sessions revoked).'
        ))
