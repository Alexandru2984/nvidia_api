import secrets

from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.db.models.signals import pre_delete
from django.dispatch import receiver


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
    """Per-user TOTP setup. `secret` is stored base32 (plaintext) — acceptable
    for our threat model since DB compromise here implies VPS compromise. The
    real defense is `enabled=False` until verified, and recovery codes are
    HMAC-hashed (never stored plaintext)."""
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        related_name='two_factor',
        on_delete=models.CASCADE,
    )
    # Secret is now Fernet-encrypted at rest (key derived from SECRET_KEY).
    # Old plaintext rows are auto-migrated on first read.
    secret = models.CharField(max_length=256)
    enabled = models.BooleanField(default=False)
    recovery_codes = models.JSONField(default=list)  # list of HMAC-SHA256 hex digests
    enrolled_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    # Replay protection: highest TOTP step (epoch//30) we've already accepted.
    last_totp_step = models.BigIntegerField(default=0)
    # Brute-force lockout
    failed_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


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
    temperature = models.FloatField(default=0.7)
    max_tokens = models.PositiveIntegerField(default=1024)
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

    def __str__(self):
        return f'{self.title} ({self.model_id})'


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
    integrity_tag = models.CharField(max_length=64)

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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        indexes = [
            GinIndex(
                fields=['content'],
                name='chat_msg_content_trgm',
                opclasses=['gin_trgm_ops'],
            ),
        ]

    def __str__(self):
        return f'{self.role}: {self.content[:40]}'


def _attachment_path(instance, filename):
    rand = secrets.token_hex(8)
    return f'attachments/{instance.user_id}/{rand}/{filename}'


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
        indexes = [models.Index(fields=['user', 'created_at'])]
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


@receiver(pre_delete, sender=Attachment)
def _attachment_pre_delete(sender, instance, **kwargs):
    if instance.file:
        instance.file.delete(save=False)
