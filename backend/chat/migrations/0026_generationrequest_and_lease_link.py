from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('chat', '0025_alter_adminauditevent_integrity_tag'),
    ]

    operations = [
        migrations.CreateModel(
            name='GenerationRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('idempotency_key', models.UUIDField(editable=False)),
                ('operation', models.CharField(choices=[('send', 'Send'), ('regenerate', 'Regenerate')], max_length=12)),
                ('request_fingerprint', models.CharField(editable=False, max_length=64)),
                ('target_message_id', models.PositiveBigIntegerField(blank=True, null=True)),
                ('state', models.CharField(choices=[('queued', 'Queued'), ('streaming', 'Streaming'), ('completed', 'Completed'), ('canceled', 'Canceled'), ('failed', 'Failed'), ('interrupted', 'Interrupted')], default='queued', max_length=12)),
                ('outcome_code', models.CharField(blank=True, default='', max_length=64)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('assistant_message', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='chat.message')),
                ('conversation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='generation_requests', to='chat.conversation')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='generation_requests', to=settings.AUTH_USER_MODEL)),
                ('user_message', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to='chat.message')),
            ],
            options={
                'indexes': [
                    models.Index(fields=['conversation', '-created_at'], name='chat_genreq_convo_created_idx'),
                    models.Index(fields=['state', 'updated_at'], name='chat_genreq_state_updated_idx'),
                ],
                'constraints': [
                    models.UniqueConstraint(fields=('user', 'idempotency_key'), name='chat_generation_request_user_key_unique'),
                    models.CheckConstraint(condition=models.Q(models.Q(('operation', 'send'), ('target_message_id__isnull', True)), models.Q(('operation', 'regenerate'), ('target_message_id__isnull', False)), _connector='OR'), name='chat_generation_request_target_shape'),
                    models.CheckConstraint(condition=models.Q(('state__in', ['queued', 'streaming', 'completed', 'canceled', 'failed', 'interrupted'])), name='chat_generation_request_state_valid'),
                    models.CheckConstraint(condition=models.Q(models.Q(('completed_at__isnull', True), ('state__in', ['queued', 'streaming'])), models.Q(('completed_at__isnull', False), ('state__in', ['completed', 'canceled', 'failed', 'interrupted'])), _connector='OR'), name='chat_generation_request_completion_shape'),
                ],
            },
        ),
        migrations.AddField(
            model_name='conversationgenerationlease',
            name='generation_request',
            field=models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='lease', to='chat.generationrequest'),
        ),
    ]
