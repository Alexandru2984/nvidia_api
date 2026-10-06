from django.contrib.postgres.indexes import GinIndex
from django.db import migrations


def create_postgres_search_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('CREATE EXTENSION IF NOT EXISTS pg_trgm')
        cursor.execute(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_convo_title_trgm '
            'ON chat_conversation USING gin (title gin_trgm_ops)'
        )
        cursor.execute(
            'CREATE INDEX CONCURRENTLY IF NOT EXISTS chat_msg_content_trgm '
            'ON chat_message USING gin (content gin_trgm_ops)'
        )


def drop_postgres_search_indexes(apps, schema_editor):
    if schema_editor.connection.vendor != 'postgresql':
        return
    with schema_editor.connection.cursor() as cursor:
        cursor.execute('DROP INDEX CONCURRENTLY IF EXISTS chat_convo_title_trgm')
        cursor.execute('DROP INDEX CONCURRENTLY IF EXISTS chat_msg_content_trgm')


class Migration(migrations.Migration):

    atomic = False

    dependencies = [
        ('chat', '0016_conversation_archived_at_conversation_is_pinned_and_more'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            database_operations=[
                migrations.RunPython(
                    create_postgres_search_indexes,
                    drop_postgres_search_indexes,
                ),
            ],
            state_operations=[
                migrations.AddIndex(
                    model_name='conversation',
                    index=GinIndex(
                        fields=['title'],
                        name='chat_convo_title_trgm',
                        opclasses=['gin_trgm_ops'],
                    ),
                ),
                migrations.AddIndex(
                    model_name='message',
                    index=GinIndex(
                        fields=['content'],
                        name='chat_msg_content_trgm',
                        opclasses=['gin_trgm_ops'],
                    ),
                ),
            ],
        ),
    ]
