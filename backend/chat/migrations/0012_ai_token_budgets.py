from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012 - Django migration declaration
        ('chat', '0011_case_insensitive_identity_uniqueness'),
    ]

    operations = [  # noqa: RUF012 - Django migration declaration
        migrations.AddField(
            model_name='dailyaiusage',
            name='completion_tokens',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='dailyaiusage',
            name='prompt_tokens',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='dailyaiusage',
            name='reserved_tokens',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='dailyaiusage',
            name='unmetered_chat_requests',
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='globalaiusage',
            name='completion_tokens',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='globalaiusage',
            name='prompt_tokens',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='globalaiusage',
            name='reserved_tokens',
            field=models.PositiveBigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='globalaiusage',
            name='unmetered_chat_requests',
            field=models.PositiveIntegerField(default=0),
        ),
    ]
