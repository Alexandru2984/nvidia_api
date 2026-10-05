from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [  # noqa: RUF012 - Django migration declaration
        ('chat', '0010_daily_ai_usage_global_ai_usage'),
    ]

    operations = [  # noqa: RUF012 - Django migration declaration
        migrations.RunSQL(
            sql=(
                'CREATE UNIQUE INDEX auth_user_username_ci_unique '
                'ON auth_user (LOWER(username))'
            ),
            reverse_sql='DROP INDEX IF EXISTS auth_user_username_ci_unique',
        ),
        migrations.RunSQL(
            sql=(
                'CREATE UNIQUE INDEX auth_user_email_ci_unique '
                "ON auth_user (LOWER(email)) WHERE email <> ''"
            ),
            reverse_sql='DROP INDEX IF EXISTS auth_user_email_ci_unique',
        ),
    ]
