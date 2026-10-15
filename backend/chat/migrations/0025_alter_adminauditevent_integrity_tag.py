from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('chat', '0024_providerdisclosureacceptance'),
    ]

    operations = [
        migrations.AlterField(
            model_name='adminauditevent',
            name='integrity_tag',
            field=models.CharField(max_length=104),
        ),
    ]
