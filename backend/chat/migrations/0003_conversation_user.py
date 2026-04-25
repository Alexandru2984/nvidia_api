from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0002_emailverification'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='conversation',
            name='user',
            field=models.ForeignKey(
                default=1,  # backfill existing rows to the original superuser
                on_delete=models.deletion.CASCADE,
                related_name='conversations',
                to=settings.AUTH_USER_MODEL,
            ),
            preserve_default=False,
        ),
    ]
