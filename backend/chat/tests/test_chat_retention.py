"""Opt-in archived-chat lifecycle and linked-data deletion guarantees."""
from datetime import timedelta
from io import StringIO
from pathlib import Path

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import IntegrityError, connection, transaction
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from chat.models import (
    Attachment,
    ChatHistoryRetention,
    Conversation,
    ConversationGenerationLease,
    Message,
)
from chat.models_catalog import DEFAULT_MODEL_ID


def _archive_at(conversation, when):
    Conversation.objects.filter(pk=conversation.pk).update(
        archived_at=when,
        updated_at=when,
    )


def _conversation(user, title):
    return Conversation.objects.create(
        user=user,
        title=title,
        model_id=DEFAULT_MODEL_ID,
    )


@pytest.mark.django_db
class TestChatRetentionAPI:
    def test_retention_endpoint_requires_authentication(self, client):
        assert client.get('/api/account/chat-retention/').status_code in (401, 403)
        assert client.patch(
            '/api/account/chat-retention/',
            {'archived_days': 30},
            format='json',
        ).status_code in (401, 403)

    def test_default_is_keep_forever_without_creating_metadata(self, auth_client):
        response = auth_client.get('/api/account/chat-retention/')

        assert response.status_code == 200
        assert response.json() == {
            'archived_days': 0,
            'choices': [
                {'days': 0, 'label': 'Keep until I delete'},
                {'days': 30, 'label': 'Delete after 30 days'},
                {'days': 90, 'label': 'Delete after 90 days'},
                {'days': 180, 'label': 'Delete after 180 days'},
                {'days': 365, 'label': 'Delete after 365 days'},
            ],
            'scope': 'archived_inactive_conversations',
        }
        assert not ChatHistoryRetention.objects.exists()

    def test_owner_can_enable_and_disable_archived_retention(
        self,
        auth_client,
        user,
        caplog,
    ):
        caplog.set_level('INFO', logger='security')

        enabled = auth_client.patch(
            '/api/account/chat-retention/',
            {'archived_days': 90},
            format='json',
        )
        disabled = auth_client.patch(
            '/api/account/chat-retention/',
            {'archived_days': 0},
            format='json',
        )

        assert enabled.status_code == disabled.status_code == 200
        assert enabled.json()['archived_days'] == 90
        assert disabled.json()['archived_days'] == 0
        assert ChatHistoryRetention.objects.get(user=user).archived_days == 0
        messages = '\n'.join(record.getMessage() for record in caplog.records)
        assert f'event=chat_retention_changed user_id={user.pk} archived_days=90' in messages
        assert 'event=chat_retention_changed' in messages

    @pytest.mark.parametrize('value', [True, '30', 1, 29, 366, None])
    def test_invalid_retention_is_rejected(self, auth_client, value):
        response = auth_client.patch(
            '/api/account/chat-retention/',
            {'archived_days': value},
            format='json',
        )

        assert response.status_code == 400
        assert response.json()['code'] == 'invalid_chat_retention'
        assert not ChatHistoryRetention.objects.exists()

    def test_preferences_are_owner_scoped(
        self,
        auth_client,
        other_client,
        user,
        other_user,
    ):
        assert auth_client.patch(
            '/api/account/chat-retention/',
            {'archived_days': 30},
            format='json',
        ).status_code == 200

        assert other_client.get('/api/account/chat-retention/').json()['archived_days'] == 0
        assert ChatHistoryRetention.objects.get(user=user).archived_days == 30
        assert not ChatHistoryRetention.objects.filter(user=other_user).exists()

    def test_database_rejects_unknown_retention_days(self, user):
        with pytest.raises(IntegrityError), transaction.atomic():
            ChatHistoryRetention.objects.create(user=user, archived_days=14)


@pytest.mark.django_db
class TestChatRetentionCleanup:
    def test_deletes_only_old_archived_conversation_and_linked_data(
        self,
        user,
        settings,
    ):
        settings.CHAT_RETENTION_DELETE_BATCH_SIZE = 100
        ChatHistoryRetention.objects.create(user=user, archived_days=30)
        old = _conversation(user, 'old archived')
        message = Message.objects.create(
            conversation=old,
            role='user',
            content='private history',
        )
        attachment = Attachment.objects.create(
            user=user,
            message=message,
            file=SimpleUploadedFile('linked.txt', b'linked', content_type='text/plain'),
            original_name='linked.txt',
            mime_type='text/plain',
            size=6,
            kind=Attachment.KIND_DOCUMENT,
            extracted_text='linked',
        )
        attachment_path = attachment.file.path
        recent = _conversation(user, 'recent archived')
        active = _conversation(user, 'active old')
        old_time = timezone.now() - timedelta(days=31)
        _archive_at(old, old_time)
        _archive_at(recent, timezone.now() - timedelta(days=29))
        Conversation.objects.filter(pk=active.pk).update(updated_at=old_time)

        output = StringIO()
        call_command('cleanup_attachments', stdout=output)

        assert not Conversation.objects.filter(pk=old.pk).exists()
        assert Conversation.objects.filter(pk=recent.pk).exists()
        assert Conversation.objects.filter(pk=active.pk).exists()
        assert not Message.objects.filter(pk=message.pk).exists()
        assert not Attachment.objects.filter(pk=attachment.pk).exists()
        assert not Path(attachment_path).exists()
        assert '1 retained archived conversations (1 messages, 15 bytes)' in output.getvalue()

    def test_keep_forever_and_missing_preferences_never_delete(
        self,
        user,
        other_user,
    ):
        ChatHistoryRetention.objects.create(user=user, archived_days=0)
        explicit = _conversation(user, 'explicit forever')
        implicit = _conversation(other_user, 'implicit forever')
        old_time = timezone.now() - timedelta(days=1000)
        _archive_at(explicit, old_time)
        _archive_at(implicit, old_time)

        call_command('cleanup_attachments', stdout=StringIO())

        assert Conversation.objects.filter(pk__in=[explicit.pk, implicit.pk]).count() == 2

    def test_active_generation_lease_excludes_archived_conversation(self, user):
        ChatHistoryRetention.objects.create(user=user, archived_days=30)
        conversation = _conversation(user, 'leased')
        _archive_at(conversation, timezone.now() - timedelta(days=31))
        ConversationGenerationLease.objects.create(
            conversation=conversation,
            token='00000000-0000-4000-8000-000000000001',
            expires_at=timezone.now() + timedelta(minutes=5),
        )

        call_command('cleanup_attachments', stdout=StringIO())

        assert Conversation.objects.filter(pk=conversation.pk).exists()
        assert ConversationGenerationLease.objects.filter(conversation=conversation).exists()

    def test_locked_conversation_query_has_no_nullable_lease_join(self, user):
        ChatHistoryRetention.objects.create(user=user, archived_days=30)
        conversation = _conversation(user, 'postgres lock regression')
        _archive_at(conversation, timezone.now() - timedelta(days=31))

        with CaptureQueriesContext(connection) as queries:
            call_command('cleanup_attachments', stdout=StringIO())

        locked_conversation_queries = [
            item['sql']
            for item in queries.captured_queries
            if 'FROM "chat_conversation"' in item['sql']
            and f'"chat_conversation"."id" = {conversation.pk}' in item['sql']
            and 'LIMIT 1' in item['sql']
        ]
        assert locked_conversation_queries
        assert all('JOIN' not in query for query in locked_conversation_queries)
        assert not Conversation.objects.filter(pk=conversation.pk).exists()

    def test_cleanup_is_bounded_to_configured_batch(self, user, settings):
        settings.CHAT_RETENTION_DELETE_BATCH_SIZE = 1
        ChatHistoryRetention.objects.create(user=user, archived_days=30)
        oldest = _conversation(user, 'oldest')
        newer = _conversation(user, 'newer')
        _archive_at(oldest, timezone.now() - timedelta(days=40))
        _archive_at(newer, timezone.now() - timedelta(days=35))

        call_command('cleanup_attachments', stdout=StringIO())

        assert not Conversation.objects.filter(pk=oldest.pk).exists()
        assert Conversation.objects.filter(pk=newer.pk).exists()

    def test_dry_run_reports_but_preserves_retained_history(self, user, settings):
        settings.CHAT_RETENTION_DELETE_BATCH_SIZE = 100
        ChatHistoryRetention.objects.create(user=user, archived_days=30)
        conversation = _conversation(user, 'dry run')
        Message.objects.create(conversation=conversation, role='user', content='six')
        _archive_at(conversation, timezone.now() - timedelta(days=31))
        output = StringIO()

        call_command('cleanup_attachments', '--dry-run', stdout=output)

        assert Conversation.objects.filter(pk=conversation.pk).exists()
        assert '1 retention-eligible archived conversations' in output.getvalue()
        assert '1 messages' in output.getvalue()
