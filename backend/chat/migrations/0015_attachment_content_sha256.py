from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('chat', '0014_admin_audit_event'),
    ]

    operations = [
        migrations.AddField(
            model_name='attachment',
            name='content_sha256',
            field=models.CharField(blank=True, default='', editable=False, max_length=64),
        ),
        migrations.AddConstraint(
            model_name='attachment',
            constraint=models.UniqueConstraint(
                condition=models.Q(message__isnull=True) & ~models.Q(content_sha256=''),
                fields=('user', 'content_sha256'),
                name='unique_pending_attachment_content_per_user',
            ),
        ),
    ]
