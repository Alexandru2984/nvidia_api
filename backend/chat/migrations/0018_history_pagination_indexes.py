from django.db import migrations, models


def create_postgres_history_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_msg_convo_recent_idx '
            'ON chat_message (conversation_id, created_at DESC, id DESC)'
        )
        cursor.execute('DROP INDEX CONCURRENTLY IF EXISTS chat_attach_user_id_d1a256_idx')
        cursor.execute(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_attach_user_recent_idx '
            'ON chat_attachment (user_id, created_at DESC, id DESC)'
        )
        cursor.execute(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_attach_kind_recent_idx '
            'ON chat_attachment (user_id, kind, created_at DESC, id DESC)'
        )


def restore_postgres_history_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('DROP INDEX CONCURRENTLY IF EXISTS chat_msg_convo_recent_idx')
        cursor.execute('DROP INDEX CONCURRENTLY IF EXISTS chat_attach_kind_recent_idx')
        cursor.execute('DROP INDEX CONCURRENTLY IF EXISTS chat_attach_user_recent_idx')
        cursor.execute(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_attach_user_id_d1a256_idx '
            'ON chat_attachment (user_id, created_at)'
        )


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ('chat', '0017_conversation_search_indexes'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    create_postgres_history_indexes,
                    restore_postgres_history_indexes,
                ),
            ],
            state_operations=[
                migrations.AddIndex(
                    model_name='message',
                    index=models.Index(
                        fields=['conversation', '-created_at', '-id'],
                        name='chat_msg_convo_recent_idx',
                    ),
                ),
                migrations.RemoveIndex(
                    model_name='attachment',
                    name='chat_attach_user_id_d1a256_idx',
                ),
                migrations.AddIndex(
                    model_name='attachment',
                    index=models.Index(
                        fields=['user', '-created_at', '-id'],
                        name='chat_attach_user_recent_idx',
                    ),
                ),
                migrations.AddIndex(
                    model_name='attachment',
                    index=models.Index(
                        fields=['user', 'kind', '-created_at', '-id'],
                        name='chat_attach_kind_recent_idx',
                    ),
                ),
            ],
        ),
    ]
