from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0018_history_pagination_indexes'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AttachmentUploadAttempt',
            fields=[
                ('id', models.UUIDField(editable=False, primary_key=True, serialize=False)),
                (
                    'state',
                    models.CharField(
                        choices=[
                            ('active', 'Active'),
                            ('completed', 'Completed'),
                            ('canceled', 'Canceled'),
                        ],
                        default='active',
                        max_length=12,
                    ),
                ),
                ('owns_attachment', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                (
                    'attachment',
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name='upload_attempts',
                        to='chat.attachment',
                    ),
                ),
                (
                    'user',
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='attachment_upload_attempts',
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                'indexes': [
                    models.Index(
                        fields=['user', '-updated_at'],
                        name='chat_upload_user_updated_idx',
                    ),
                ],
            },
        ),
    ]
