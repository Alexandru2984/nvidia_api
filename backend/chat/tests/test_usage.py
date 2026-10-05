import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from chat.models import Attachment, DailyAIUsage, GlobalAIUsage, Message
from chat.usage import reserve_ai_request

pytestmark = pytest.mark.django_db


def test_usage_only_counts_current_user(auth_client, other_user, convo):
    Attachment.objects.create(user=other_user, file=SimpleUploadedFile('x.txt', b'secret'),
        original_name='x.txt', size=6, kind='document', mime_type='text/plain')
    data = auth_client.get('/api/account/usage/').json()
    assert data['conversations'] == 1
    assert data['attachments'] == 0
    assert data['storage_bytes'] == 0
    assert data['ai_today']['chat_requests'] == 0
    assert data['ai_today']['image_requests'] == 0


def test_usage_requires_session(client):
    assert client.get('/api/account/usage/').status_code == 403


def test_usage_snapshot_includes_durable_daily_counters(auth_client, user):
    DailyAIUsage.objects.create(
        user=user, day=timezone.localdate(), chat_requests=3,
        image_requests=2, prompt_characters=1234,
    )
    data = auth_client.get('/api/account/usage/').json()['ai_today']
    assert data['chat_requests'] == 3
    assert data['image_requests'] == 2
    assert data['prompt_characters'] == 1234
    assert data['chat_limit'] > 3
    assert data['image_limit'] > 2
    assert data['resets_at'].endswith('Z')


def test_user_chat_limit_blocks_before_message_write(auth_client, convo, settings):
    settings.AI_USER_DAILY_CHAT_LIMIT = 0
    response = auth_client.post(
        f'/api/conversations/{convo.id}/messages/', {'content': 'do not persist'}, format='json',
    )
    assert response.status_code == 429
    assert response.json()['code'] == 'user_daily_limit'
    assert 'Retry-After' in response
    assert not Message.objects.filter(conversation=convo).exists()


def test_global_chat_limit_is_shared_between_users(user, other_user, settings):
    settings.AI_USER_DAILY_CHAT_LIMIT = 10
    settings.AI_GLOBAL_DAILY_CHAT_LIMIT = 1
    assert reserve_ai_request(user, 'chat', 10) is None
    assert reserve_ai_request(other_user, 'chat', 20) == 'global_daily_limit'
    global_usage = GlobalAIUsage.objects.get(day=timezone.localdate())
    assert global_usage.chat_requests == 1
    assert global_usage.prompt_characters == 10


def test_circuit_breaker_creates_no_usage_rows(user, settings):
    settings.AI_GENERATION_ENABLED = False
    assert reserve_ai_request(user, 'chat', 100) == 'disabled'
    assert not DailyAIUsage.objects.exists()
    assert not GlobalAIUsage.objects.exists()


def test_image_limit_blocks_before_provider_call(auth_client, settings):
    settings.AI_USER_DAILY_IMAGE_LIMIT = 0
    response = auth_client.post('/api/images/generate/', {'prompt': 'a safe test'}, format='json')
    assert response.status_code == 429
    assert response.json()['code'] == 'user_daily_limit'


def test_regenerate_quota_does_not_truncate_messages(auth_client, convo, settings):
    Message.objects.create(conversation=convo, role='user', content='first')
    target = Message.objects.create(conversation=convo, role='assistant', content='answer')
    Message.objects.create(conversation=convo, role='user', content='later')
    settings.AI_USER_DAILY_CHAT_LIMIT = 0
    ids_before = list(convo.messages.values_list('id', flat=True))
    response = auth_client.post(f'/api/messages/{target.id}/regenerate/')
    assert response.status_code == 429
    assert list(convo.messages.values_list('id', flat=True)) == ids_before
