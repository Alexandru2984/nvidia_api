from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0015_attachment_content_sha256'),
    ]

    operations = [
        migrations.AddField(
            model_name='conversation',
            name='archived_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='conversation',
            name='is_pinned',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterModelOptions(
            name='conversation',
            options={'ordering': ['-is_pinned', '-updated_at']},
        ),
        migrations.AddIndex(
            model_name='conversation',
            index=models.Index(
                fields=['user', 'archived_at', '-is_pinned', '-updated_at'],
                name='chat_convo_owner_view_idx',
            ),
        ),
    ]
