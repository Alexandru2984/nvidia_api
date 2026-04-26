"""Tests for attachment upload, MIME sniffing, quota, text extraction."""
import io
import os
import threading
from unittest.mock import patch

import pytest
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile

from chat.attachments import detect_mime, kind_for_mime, extract_text
from chat.models import Attachment, Message


def _png_bytes():
    """Smallest valid PNG (1x1 white pixel)."""
    return bytes.fromhex(
        '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4'
        '890000000d49444154789c63f8ffff3f0005fe02fef9352eaa0000000049454e44ae426082'
    )


def _txt_upload(name='hello.txt', text='hello world'):
    return SimpleUploadedFile(name, text.encode(), content_type='text/plain')


def _img_upload(name='pic.png'):
    return SimpleUploadedFile(name, _png_bytes(), content_type='image/png')


@pytest.mark.django_db
class TestUploadHappyPath:
    def test_upload_image_creates_attachment(self, auth_client, user):
        r = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        assert r.status_code == 201, r.content
        body = r.json()
        assert body['kind'] == 'image'
        assert body['mime_type'] == 'image/png'
        assert body['size'] > 0
        assert body['has_text'] is False
        att = Attachment.objects.get(pk=body['id'])
        assert att.user == user
        # File written under /attachments/<user_id>/<rand>/...
        assert f'/{user.id}/' in att.file.name

    def test_upload_txt_extracts_text(self, auth_client):
        r = auth_client.post('/api/attachments/upload/', {'file': _txt_upload(text='ALPHA BETA')}, format='multipart')
        assert r.status_code == 201
        att = Attachment.objects.get(pk=r.json()['id'])
        assert att.kind == 'document'
        assert 'ALPHA BETA' in att.extracted_text

    def test_filename_sanitized(self, auth_client):
        # Path traversal / special chars should be stripped.
        bad = SimpleUploadedFile('../../etc/passwd.txt', b'x', content_type='text/plain')
        r = auth_client.post('/api/attachments/upload/', {'file': bad}, format='multipart')
        assert r.status_code == 201
        # original_name should not have slashes
        assert '/' not in r.json()['original_name']


@pytest.mark.django_db
class TestUploadValidation:
    def test_no_file_returns_400(self, auth_client):
        r = auth_client.post('/api/attachments/upload/', {}, format='multipart')
        assert r.status_code == 400

    def test_file_too_large_returns_413(self, auth_client, settings):
        settings.MAX_ATTACHMENT_SIZE = 100  # tiny cap for the test
        big = SimpleUploadedFile('big.txt', b'x' * 200, content_type='text/plain')
        r = auth_client.post('/api/attachments/upload/', {'file': big}, format='multipart')
        assert r.status_code == 413

    def test_unsupported_mime_returns_415(self, auth_client):
        bad = SimpleUploadedFile('a.exe', b'MZ', content_type='application/x-msdownload')
        r = auth_client.post('/api/attachments/upload/', {'file': bad}, format='multipart')
        assert r.status_code == 415

    def test_unauthenticated_blocked(self, client):
        r = client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        assert r.status_code in (401, 403)


@pytest.mark.django_db
class TestQuota:
    def test_quota_exceeded_returns_413(self, auth_client, user, settings):
        settings.MAX_USER_STORAGE = 50
        # First 30B upload OK
        f1 = SimpleUploadedFile('a.txt', b'x' * 30, content_type='text/plain')
        assert auth_client.post('/api/attachments/upload/', {'file': f1}, format='multipart').status_code == 201
        # Second 30B upload pushes total over 50B → 413
        f2 = SimpleUploadedFile('b.txt', b'x' * 30, content_type='text/plain')
        r2 = auth_client.post('/api/attachments/upload/', {'file': f2}, format='multipart')
        assert r2.status_code == 413
        # Only the first upload exists
        assert Attachment.objects.filter(user=user).count() == 1

    def test_quota_scoped_per_user(self, auth_client, other_client, settings):
        settings.MAX_USER_STORAGE = 50
        f1 = SimpleUploadedFile('a.txt', b'x' * 40, content_type='text/plain')
        assert auth_client.post('/api/attachments/upload/', {'file': f1}, format='multipart').status_code == 201
        # Other user has separate quota
        f2 = SimpleUploadedFile('b.txt', b'x' * 40, content_type='text/plain')
        assert other_client.post('/api/attachments/upload/', {'file': f2}, format='multipart').status_code == 201


@pytest.mark.django_db
class TestListAttachments:
    def test_lists_only_own(self, auth_client, other_client):
        auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        other_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        r = auth_client.get('/api/attachments/')
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_filter_by_kind(self, auth_client):
        auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        auth_client.post('/api/attachments/upload/', {'file': _txt_upload()}, format='multipart')
        r = auth_client.get('/api/attachments/?kind=image')
        assert r.status_code == 200
        assert len(r.json()) == 1
        assert r.json()[0]['kind'] == 'image'


@pytest.mark.django_db
class TestDeleteAttachment:
    def test_delete_orphan(self, auth_client, user):
        r = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        att_id = r.json()['id']
        d = auth_client.delete(f'/api/attachments/{att_id}/')
        assert d.status_code == 204
        assert not Attachment.objects.filter(pk=att_id).exists()

    def test_cannot_delete_linked(self, auth_client, user, convo):
        r = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        att = Attachment.objects.get(pk=r.json()['id'])
        msg = Message.objects.create(conversation=convo, role='user', content='x')
        att.message = msg
        att.save()
        d = auth_client.delete(f'/api/attachments/{att.id}/')
        assert d.status_code == 409

    def test_cannot_delete_other_users(self, auth_client, other_client):
        r = other_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        d = auth_client.delete(f'/api/attachments/{r.json()["id"]}/')
        assert d.status_code == 404


@pytest.mark.django_db
class TestMimeSniffing:
    def test_detect_mime_uses_declared(self):
        f = SimpleUploadedFile('x.png', b'', content_type='image/png')
        assert detect_mime(f) == 'image/png'

    def test_detect_mime_falls_back_to_extension(self):
        # Some clients send octet-stream — we recover from the extension.
        f = SimpleUploadedFile('doc.pdf', b'', content_type='application/octet-stream')
        assert detect_mime(f) == 'application/pdf'

    def test_kind_for_mime(self):
        assert kind_for_mime('image/png') == 'image'
        assert kind_for_mime('application/pdf') == 'document'
        assert kind_for_mime('application/x-evil') is None


@pytest.mark.django_db
class TestExtractText:
    def test_txt_truncation_at_cap(self, settings):
        settings.DOC_EXTRACT_MAX_CHARS = 10
        f = SimpleUploadedFile('a.txt', b'A' * 100, content_type='text/plain')
        out = extract_text(f, 'text/plain')
        assert len(out) == 10

    def test_pdf_extract_or_empty(self, settings):
        # Without a real PDF the parser raises; we should swallow and return ''.
        f = SimpleUploadedFile('a.pdf', b'not a real pdf', content_type='application/pdf')
        out = extract_text(f, 'application/pdf')
        assert out == ''


@pytest.mark.django_db
class TestPerUserPath:
    def test_different_users_get_different_dirs(self, auth_client, other_client, user, other_user):
        r1 = auth_client.post('/api/attachments/upload/', {'file': _img_upload('a.png')}, format='multipart')
        r2 = other_client.post('/api/attachments/upload/', {'file': _img_upload('b.png')}, format='multipart')
        a1 = Attachment.objects.get(pk=r1.json()['id'])
        a2 = Attachment.objects.get(pk=r2.json()['id'])
        assert f'/{user.id}/' in a1.file.name
        assert f'/{other_user.id}/' in a2.file.name
        assert a1.file.name != a2.file.name
