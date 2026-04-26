import secrets

from django.conf import settings
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
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f'{self.title} ({self.model_id})'


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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [models.Index(fields=['user', 'created_at'])]

    def __str__(self):
        return f'{self.kind}:{self.original_name} ({self.size}B)'

    @property
    def url(self):
        return self.file.url if self.file else ''


@receiver(pre_delete, sender=Attachment)
def _attachment_pre_delete(sender, instance, **kwargs):
    if instance.file:
        instance.file.delete(save=False)
