"""Tests for attachment upload, MIME sniffing, quota, text extraction."""
import hashlib

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from chat.attachments import content_sha256, detect_mime, extract_text, kind_for_mime
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
        assert body['deduplicated'] is False
        assert 'content_sha256' not in body
        att = Attachment.objects.get(pk=body['id'])
        assert att.user == user
        assert len(att.content_sha256) == 64
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
        f2 = SimpleUploadedFile('b.txt', b'y' * 30, content_type='text/plain')
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
class TestUploadDeduplication:
    def test_reuses_same_users_unlinked_content(self, auth_client, user):
        first = auth_client.post('/api/attachments/upload/', {'file': _img_upload('one.png')}, format='multipart')
        second = auth_client.post('/api/attachments/upload/', {'file': _img_upload('two.png')}, format='multipart')

        assert first.status_code == 201
        assert second.status_code == 200
        assert second.json()['deduplicated'] is True
        assert second.json()['id'] == first.json()['id']
        assert Attachment.objects.filter(user=user).count() == 1

    def test_duplicate_does_not_consume_quota_again(self, auth_client, user, settings):
        settings.MAX_USER_STORAGE = len(_png_bytes()) + 1
        first = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        second = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')

        assert first.status_code == 201
        assert second.status_code == 200
        assert Attachment.objects.filter(user=user).count() == 1

    def test_deduplication_never_crosses_users(self, auth_client, other_client):
        first = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        second = other_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')

        assert first.status_code == 201
        assert second.status_code == 201
        assert first.json()['id'] != second.json()['id']

    def test_linked_attachment_is_not_reused(self, auth_client, user, convo):
        first = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        attachment = Attachment.objects.get(pk=first.json()['id'])
        message = Message.objects.create(conversation=convo, role='user', content='sent')
        attachment.message = message
        attachment.save(update_fields=['message'])

        second = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        assert second.status_code == 201
        assert second.json()['id'] != first.json()['id']
        assert Attachment.objects.filter(user=user).count() == 2


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
        assert 'content_sha256' not in r.json()[0]


@pytest.mark.django_db
class TestDocumentPreview:
    def test_owner_can_preview_extracted_text_without_caching(self, auth_client):
        uploaded = auth_client.post(
            '/api/attachments/upload/',
            {'file': _txt_upload(text='private preview text')},
            format='multipart',
        )
        response = auth_client.get(f'/api/attachments/{uploaded.json()["id"]}/preview/')

        assert response.status_code == 200
        assert response.json() == {
            'text': 'private preview text',
            'characters': 20,
            'truncated': False,
        }
        assert 'private' in response['Cache-Control']
        assert 'no-store' in response['Cache-Control']
        assert response['Pragma'] == 'no-cache'

    def test_preview_is_truncated_at_dedicated_limit(self, auth_client, settings):
        settings.ATTACHMENT_PREVIEW_MAX_CHARS = 8
        uploaded = auth_client.post(
            '/api/attachments/upload/',
            {'file': _txt_upload(text='abcdefghijkl')},
            format='multipart',
        )
        response = auth_client.get(f'/api/attachments/{uploaded.json()["id"]}/preview/')

        assert response.json() == {'text': 'abcdefgh', 'characters': 12, 'truncated': True}

    def test_preview_is_owner_scoped(self, auth_client, other_client):
        uploaded = auth_client.post('/api/attachments/upload/', {'file': _txt_upload()}, format='multipart')
        response = other_client.get(f'/api/attachments/{uploaded.json()["id"]}/preview/')
        assert response.status_code == 404

    def test_image_has_no_text_preview(self, auth_client):
        uploaded = auth_client.post('/api/attachments/upload/', {'file': _img_upload()}, format='multipart')
        response = auth_client.get(f'/api/attachments/{uploaded.json()["id"]}/preview/')
        assert response.status_code == 400


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
    def test_detect_mime_uses_content(self):
        f = SimpleUploadedFile('x.png', _png_bytes(), content_type='application/octet-stream')
        assert detect_mime(f) == 'image/png'

    def test_detect_mime_falls_back_to_extension(self):
        # Some clients send octet-stream — we recover from the extension.
        f = SimpleUploadedFile('doc.pdf', b'%PDF-1.7\n', content_type='application/octet-stream')
        assert detect_mime(f) == 'application/pdf'

    def test_kind_for_mime(self):
        assert kind_for_mime('image/png') == 'image'
        assert kind_for_mime('application/pdf') == 'document'
        assert kind_for_mime('application/x-evil') is None

    def test_content_hash_rewinds_upload(self):
        upload = _img_upload()
        expected = hashlib.sha256(_png_bytes()).hexdigest()
        assert content_sha256(upload) == expected
        assert upload.read() == _png_bytes()


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
