import secrets

from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models.signals import pre_delete
from django.dispatch import receiver

from .generation import (
    MAX_TOKENS_MAX,
    MAX_TOKENS_MIN,
    TEMPERATURE_MAX,
    TEMPERATURE_MIN,
)


class EmailVerification(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='email_verification',
        on_delete=models.CASCADE,
    )
    code_hash = models.CharField(max_length=128)
    sent_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f'EmailVerification(user={self.user_id}, expires={self.expires_at:%Y-%m-%d %H:%M})'


class PasswordReset(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='password_reset',
        on_delete=models.CASCADE,
    )
    code_hash = models.CharField(max_length=128)
    sent_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    attempts = models.PositiveIntegerField(default=0)

    def __str__(self):
        return f'PasswordReset(user={self.user_id}, expires={self.expires_at:%Y-%m-%d %H:%M})'


class RegistrationInvite(models.Model):
    """One-time registration capability; the plaintext code is never stored."""
    code_hash = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(db_index=True)
    used_at = models.DateTimeField(null=True, blank=True, db_index=True)
    used_by = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='registration_invite',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    def __str__(self):
        state = 'used' if self.used_at else 'unused'
        return f'RegistrationInvite(id={self.pk}, {state}, expires={self.expires_at:%Y-%m-%d %H:%M})'


class TwoFactor(models.Model):
    """Per-user TOTP setup with encrypted secrets and HMAC-hashed recovery codes."""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='two_factor',
        on_delete=models.CASCADE,
    )
    # Versioned Fernet envelope; the root key is independent of SECRET_KEY.
    # Explicitly enabled legacy rows are rewrapped after a successful TOTP use.
    secret = models.CharField(max_length=256)
    enabled = models.BooleanField(default=False)
    # Versioned key-id envelopes containing HMAC-SHA256 digests.
    recovery_codes = models.JSONField(default=list)
    enrolled_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    # Replay protection: highest TOTP step (epoch//30) we've already accepted.
    last_totp_step = models.BigIntegerField(default=0)
    # Brute-force lockout
    failed_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class AuthenticatedSession(models.Model):
    """Indexed, non-secret metadata for one authenticated Django session."""

    session = models.OneToOneField(
        'sessions.Session',
        related_name='chat_authentication',
        on_delete=models.CASCADE,
        primary_key=True,
        db_column='session_key',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='authenticated_sessions',
        on_delete=models.CASCADE,
    )
    handle = models.CharField(max_length=64, unique=True, editable=False)
    user_agent = models.CharField(max_length=300, blank=True, default='')
    ip_address = models.CharField(max_length=45, blank=True, default='')
    login_at = models.DateTimeField()
    absolute_expires_at = models.DateTimeField(db_index=True)

    class Meta:
        indexes = [
            models.Index(
                fields=['user', '-login_at'],
                name='chat_session_owner_login_idx',
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(absolute_expires_at__gte=models.F('login_at')),
                name='chat_session_absolute_after_login',
            ),
        ]

    def __str__(self):
        return f'AuthenticatedSession(user={self.user_id}, login={self.login_at:%Y-%m-%d %H:%M})'


class ProviderDisclosureAcceptance(models.Model):
    """Versioned evidence that a user saw the external-provider disclosure."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='provider_disclosure_acceptance',
        on_delete=models.CASCADE,
        primary_key=True,
    )
    version = models.PositiveSmallIntegerField()
    accepted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(version__gte=1),
                name='chat_provider_disclosure_version_positive',
            ),
        ]

    def __str__(self):
        return f'ProviderDisclosureAcceptance(user={self.user_id}, version={self.version})'


class ChatStorageGate(models.Model):
    """Singleton row serializing service-wide saved-message byte quotas."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(id=1),
                name='chat_storage_gate_singleton',
            ),
        ]

    def __str__(self):
        return 'ChatStorageGate(singleton)'


class ChatHistoryRetention(models.Model):
    """Owner-selected lifecycle for inactive archived conversations."""

    KEEP_FOREVER = 0
    DELETE_DAYS = (30, 90, 180, 365)
    DAY_CHOICES = [
        (KEEP_FOREVER, 'Keep until I delete'),
        (30, 'Delete after 30 days'),
        (90, 'Delete after 90 days'),
        (180, 'Delete after 180 days'),
        (365, 'Delete after 365 days'),
    ]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='chat_history_retention',
        on_delete=models.CASCADE,
        primary_key=True,
    )
    archived_days = models.PositiveSmallIntegerField(
        choices=DAY_CHOICES,
        default=KEEP_FOREVER,
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(archived_days__in=[0, 30, 90, 180, 365]),
                name='chat_history_retention_days_valid',
            ),
        ]

    def __str__(self):
        return f'ChatHistoryRetention(user={self.user_id}, days={self.archived_days})'


class AccountDeletionRequest(models.Model):
    """Owner-requested, cancelable deadline for complete live-account deletion."""

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='account_deletion_request',
        on_delete=models.CASCADE,
        primary_key=True,
    )
    requested_at = models.DateTimeField(auto_now_add=True)
    execute_after = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(execute_after__gte=models.F('requested_at')),
                name='chat_account_deletion_after_request',
            ),
        ]

    def __str__(self):
        return f'AccountDeletionRequest(user={self.user_id}, after={self.execute_after})'


class Conversation(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='conversations',
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=200, default='New Chat')
    model_id = models.CharField(max_length=120)
    # Per-conversation generation settings, editable from the UI.
    system_prompt = models.TextField(blank=True, default='')
    temperature = models.FloatField(
        default=0.7,
        validators=[MinValueValidator(TEMPERATURE_MIN), MaxValueValidator(TEMPERATURE_MAX)],
    )
    max_tokens = models.PositiveIntegerField(
        default=1024,
        validators=[MinValueValidator(MAX_TOKENS_MIN), MaxValueValidator(MAX_TOKENS_MAX)],
    )
    is_pinned = models.BooleanField(default=False)
    archived_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-is_pinned', '-updated_at']
        indexes = [
            models.Index(
                fields=['user', 'archived_at', '-is_pinned', '-updated_at'],
                name='chat_convo_owner_view_idx',
            ),
            GinIndex(
                fields=['title'],
                name='chat_convo_title_trgm',
                opclasses=['gin_trgm_ops'],
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(temperature__gte=TEMPERATURE_MIN)
                & models.Q(temperature__lte=TEMPERATURE_MAX),
                name='chat_convo_temperature_range',
            ),
            models.CheckConstraint(
                condition=models.Q(max_tokens__gte=MAX_TOKENS_MIN)
                & models.Q(max_tokens__lte=MAX_TOKENS_MAX),
                name='chat_convo_max_tokens_range',
            ),
            models.CheckConstraint(
                condition=~models.Q(model_id='nvidia/riva-translate-4b-instruct-v2')
                | models.Q(max_tokens__lte=4096),
                name='chat_convo_riva_token_limit',
            ),
        ]

    def __str__(self):
        return f'{self.title} ({self.model_id})'


class GenerationRequest(models.Model):
    """Durable idempotency and outcome record for one provider generation."""

    OPERATION_SEND = 'send'
    OPERATION_REGENERATE = 'regenerate'
    OPERATION_CHOICES = [
        (OPERATION_SEND, 'Send'),
        (OPERATION_REGENERATE, 'Regenerate'),
    ]

    STATE_QUEUED = 'queued'
    STATE_STREAMING = 'streaming'
    STATE_COMPLETED = 'completed'
    STATE_CANCELED = 'canceled'
    STATE_FAILED = 'failed'
    STATE_INTERRUPTED = 'interrupted'
    STATE_CHOICES = [
        (STATE_QUEUED, 'Queued'),
        (STATE_STREAMING, 'Streaming'),
        (STATE_COMPLETED, 'Completed'),
        (STATE_CANCELED, 'Canceled'),
        (STATE_FAILED, 'Failed'),
        (STATE_INTERRUPTED, 'Interrupted'),
    ]
    ACTIVE_STATES = (STATE_QUEUED, STATE_STREAMING)
    REPLAYABLE_STATES = (STATE_COMPLETED, STATE_CANCELED)
    TERMINAL_STATES = (
        STATE_COMPLETED,
        STATE_CANCELED,
        STATE_FAILED,
        STATE_INTERRUPTED,
    )

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='generation_requests',
        on_delete=models.CASCADE,
    )
    conversation = models.ForeignKey(
        Conversation,
        related_name='generation_requests',
        on_delete=models.CASCADE,
    )
    idempotency_key = models.UUIDField(editable=False)
    operation = models.CharField(max_length=12, choices=OPERATION_CHOICES)
    # HMAC-SHA256 of the normalized request. Prompt text is not duplicated here.
    request_fingerprint = models.CharField(max_length=64, editable=False)
    # Kept as an integer because regeneration may legitimately delete its target.
    target_message_id = models.PositiveBigIntegerField(null=True, blank=True)
    state = models.CharField(max_length=12, choices=STATE_CHOICES, default=STATE_QUEUED)
    user_message = models.ForeignKey(
        'Message',
        related_name='+',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    assistant_message = models.ForeignKey(
        'Message',
        related_name='+',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    outcome_code = models.CharField(max_length=64, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'idempotency_key'],
                name='chat_generation_request_user_key_unique',
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(operation='send', target_message_id__isnull=True)
                    | models.Q(operation='regenerate', target_message_id__isnull=False)
                ),
                name='chat_generation_request_target_shape',
            ),
            models.CheckConstraint(
                condition=models.Q(state__in=[
                    'queued',
                    'streaming',
                    'completed',
                    'canceled',
                    'failed',
                    'interrupted',
                ]),
                name='chat_generation_request_state_valid',
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        state__in=['queued', 'streaming'],
                        completed_at__isnull=True,
                    )
                    | models.Q(
                        state__in=['completed', 'canceled', 'failed', 'interrupted'],
                        completed_at__isnull=False,
                    )
                ),
                name='chat_generation_request_completion_shape',
            ),
        ]
        indexes = [
            models.Index(
                fields=['conversation', '-created_at'],
                name='chat_genreq_convo_created_idx',
            ),
            models.Index(
                fields=['state', 'updated_at'],
                name='chat_genreq_state_updated_idx',
            ),
        ]

    def __str__(self):
        return f'GenerationRequest(id={self.pk}, operation={self.operation}, state={self.state})'


class ConversationGenerationLease(models.Model):
    """Cross-worker exclusion for one streamed generation per conversation."""

    conversation = models.OneToOneField(
        Conversation,
        related_name='generation_lease',
        on_delete=models.CASCADE,
        primary_key=True,
    )
    token = models.UUIDField(editable=False)
    generation_request = models.OneToOneField(
        GenerationRequest,
        related_name='lease',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    reserved_messages = models.PositiveSmallIntegerField(default=0)
    reserved_bytes = models.PositiveBigIntegerField(default=0)
    acquired_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(db_index=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(reserved_messages__lte=2),
                name='chat_generation_reserved_messages_range',
            ),
        ]

    def __str__(self):
        return f'ConversationGenerationLease(conversation={self.conversation_id})'


class DailyAIUsage(models.Model):
    """Durable per-user provider budget for one UTC day."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='daily_ai_usage',
        on_delete=models.CASCADE,
    )
    day = models.DateField()
    chat_requests = models.PositiveIntegerField(default=0)
    image_requests = models.PositiveIntegerField(default=0)
    prompt_characters = models.PositiveBigIntegerField(default=0)
    prompt_tokens = models.PositiveBigIntegerField(default=0)
    completion_tokens = models.PositiveBigIntegerField(default=0)
    reserved_tokens = models.PositiveBigIntegerField(default=0)
    unmetered_chat_requests = models.PositiveIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['user', 'day'], name='unique_daily_ai_usage'),
        ]
        indexes = [models.Index(fields=['day'])]


class GlobalAIUsage(models.Model):
    """Global circuit-breaker counter shared by every user and worker."""
    day = models.DateField(unique=True)
    chat_requests = models.PositiveIntegerField(default=0)
    image_requests = models.PositiveIntegerField(default=0)
    prompt_characters = models.PositiveBigIntegerField(default=0)
    prompt_tokens = models.PositiveBigIntegerField(default=0)
    completion_tokens = models.PositiveBigIntegerField(default=0)
    reserved_tokens = models.PositiveBigIntegerField(default=0)
    unmetered_chat_requests = models.PositiveIntegerField(default=0)


class AdminAuditEvent(models.Model):
    """Privacy-minimized, append-only mirror of a Django admin LogEntry."""
    ACTION_CHOICES = (
        ('add', 'Add'),
        ('change', 'Change'),
        ('delete', 'Delete'),
    )

    occurred_at = models.DateTimeField(auto_now_add=True, db_index=True)
    admin_log_id = models.PositiveBigIntegerField(unique=True)
    actor_user_id = models.PositiveBigIntegerField(db_index=True)
    action = models.CharField(max_length=10, choices=ACTION_CHOICES)
    model_label = models.CharField(max_length=150, db_index=True)
    object_ref = models.CharField(max_length=64)
    changed_fields = models.JSONField(default=list)
    integrity_tag = models.CharField(max_length=104)

    class Meta:
        ordering = ['-occurred_at']

    def __str__(self):
        return f'AdminAuditEvent(id={self.pk}, action={self.action}, model={self.model_label})'


class Message(models.Model):
    ROLE_CHOICES = [
        ('user', 'user'),
        ('assistant', 'assistant'),
    ]
    conversation = models.ForeignKey(Conversation, related_name='messages', on_delete=models.CASCADE)
    role = models.CharField(max_length=16, choices=ROLE_CHOICES)
    content = models.TextField()
    # Database-derived rather than application-maintained, so multi-byte UTF-8
    # content cannot undercount quota usage and bulk writes cannot drift it.
    content_bytes = models.GeneratedField(
        expression=models.Func(
            models.F('content'),
            function='OCTET_LENGTH',
            output_field=models.PositiveBigIntegerField(),
        ),
        output_field=models.PositiveBigIntegerField(),
        db_persist=True,
        editable=False,
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        indexes = [
            GinIndex(
                fields=['content'],
                name='chat_msg_content_trgm',
                opclasses=['gin_trgm_ops'],
            ),
            models.Index(
                fields=['conversation', '-created_at', '-id'],
                name='chat_msg_convo_recent_idx',
            ),
        ]

    def __str__(self):
        return f'{self.role}: {self.content[:40]}'


def _attachment_path(instance, filename):
    rand = secrets.token_hex(8)
    return f'attachments/{instance.user_id}/{rand}/{filename}'


class PendingFileDeletion(models.Model):
    """Durable outbox for storage deletion after the owning DB row commits."""

    file_name = models.CharField(max_length=500, unique=True)
    attempts = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'PendingFileDeletion(id={self.pk}, attempts={self.attempts})'


class Attachment(models.Model):
    KIND_IMAGE = 'image'
    KIND_DOCUMENT = 'document'
    KIND_GENERATED = 'generated_image'
    KIND_CHOICES = [
        (KIND_IMAGE, 'Image'),
        (KIND_DOCUMENT, 'Document'),
        (KIND_GENERATED, 'Generated Image'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='attachments',
        on_delete=models.CASCADE,
    )
    message = models.ForeignKey(
        Message,
        related_name='attachments',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    file = models.FileField(upload_to=_attachment_path)
    original_name = models.CharField(max_length=255)
    mime_type = models.CharField(max_length=120)
    size = models.PositiveIntegerField()
    kind = models.CharField(max_length=20, choices=KIND_CHOICES)
    extracted_text = models.TextField(blank=True, default='')
    # Internal-only, secret-keyed, owner-scoped HMAC-SHA256. Never expose it through an API.
    content_sha256 = models.CharField(max_length=64, blank=True, default='', editable=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(
                fields=['user', '-created_at', '-id'],
                name='chat_attach_user_recent_idx',
            ),
            models.Index(
                fields=['user', 'kind', '-created_at', '-id'],
                name='chat_attach_kind_recent_idx',
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'content_sha256'],
                condition=models.Q(message__isnull=True) & ~models.Q(content_sha256=''),
                name='unique_pending_attachment_content_per_user',
            ),
        ]

    def __str__(self):
        return f'{self.kind}:{self.original_name} ({self.size}B)'

    @property
    def url(self):
        from django.urls import reverse
        return reverse('attachment-download', args=[self.pk]) if self.file else ''


class AttachmentUploadAttempt(models.Model):
    """Durable coordination record for one browser upload attempt.

    The client-generated UUID lets a cancellation request race safely with the
    upload across Gunicorn workers.  An attempt only owns an attachment when it
    created that row; deduplication may point several attempts at an older file
    which cancellation must never delete.
    """

    STATE_ACTIVE = 'active'
    STATE_COMPLETED = 'completed'
    STATE_CANCELED = 'canceled'
    STATE_CHOICES = [
        (STATE_ACTIVE, 'Active'),
        (STATE_COMPLETED, 'Completed'),
        (STATE_CANCELED, 'Canceled'),
    ]

    id = models.UUIDField(primary_key=True, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name='attachment_upload_attempts',
        on_delete=models.CASCADE,
    )
    state = models.CharField(max_length=12, choices=STATE_CHOICES, default=STATE_ACTIVE)
    attachment = models.ForeignKey(
        Attachment,
        related_name='upload_attempts',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    owns_attachment = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(
                fields=['user', '-updated_at'],
                name='chat_upload_user_updated_idx',
            ),
        ]


@receiver(pre_delete, sender=Attachment)
def _attachment_pre_delete(sender, instance, using, **kwargs):
    if instance.file:
        # Import lazily to avoid the helper's model import during app loading.
        from .file_deletions import enqueue_file_deletion

        enqueue_file_deletion(
            instance.file.storage,
            instance.file.name,
            using=using,
        )
