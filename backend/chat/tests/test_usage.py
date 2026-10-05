import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from chat.models import Attachment

pytestmark = pytest.mark.django_db


def test_usage_only_counts_current_user(auth_client, other_user, convo):
    Attachment.objects.create(user=other_user, file=SimpleUploadedFile('x.txt', b'secret'),
        original_name='x.txt', size=6, kind='document', mime_type='text/plain')
    data = auth_client.get('/api/account/usage/').json()
    assert data['conversations'] == 1
    assert data['attachments'] == 0
    assert data['storage_bytes'] == 0


def test_usage_requires_session(client):
    assert client.get('/api/account/usage/').status_code == 403
