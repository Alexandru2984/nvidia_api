"""Tests for attachment upload, MIME sniffing, quota, text extraction."""
import hashlib
import hmac
import uuid
from pathlib import Path
from unittest import mock

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import transaction

from chat.attachments import (
    DocumentParserError,
    content_fingerprint,
    detect_mime,
    extract_text,
    kind_for_mime,
)
from chat.malware import CLEAN, INFECTED, MalwareScanError
from chat.models import Attachment, AttachmentUploadAttempt, Message


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

    @mock.patch('chat.views.detect_mime')
    @mock.patch('chat.views.scan_attachment', return_value=INFECTED)
    def test_malware_is_rejected_before_type_parsing(
        self, scan, detect_mime_mock, auth_client, user, settings,
    ):
        settings.ATTACHMENT_MALWARE_SCAN_REQUIRED = True
        response = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload('private-name.png')},
            format='multipart',
        )

        assert response.status_code == 422
        assert response.json() == {
            'error': 'The file was rejected by the security scanner.',
            'code': 'attachment_malware_detected',
        }
        scan.assert_called_once()
        detect_mime_mock.assert_not_called()
        assert not Attachment.objects.filter(user=user).exists()

    @mock.patch('chat.views.scan_attachment', side_effect=MalwareScanError)
    def test_scanner_outage_fails_closed(self, scan, auth_client, user, settings):
        settings.ATTACHMENT_MALWARE_SCAN_REQUIRED = True
        response = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload()},
            format='multipart',
        )

        assert response.status_code == 503
        assert response.json()['code'] == 'attachment_scanner_unavailable'
        assert response['Retry-After'] == '60'
        assert not Attachment.objects.filter(user=user).exists()

    @mock.patch('chat.views.extract_text', side_effect=DocumentParserError)
    def test_document_parser_outage_fails_closed(self, extract, auth_client, user):
        upload = SimpleUploadedFile('private.pdf', b'%PDF-1.7\n', content_type='application/pdf')
        response = auth_client.post(
            '/api/attachments/upload/',
            {'file': upload},
            format='multipart',
        )

        assert response.status_code == 503
        assert response.json() == {
            'error': 'Document processing is temporarily unavailable. Try again later.',
            'code': 'attachment_parser_unavailable',
        }
        assert response['Retry-After'] == '60'
        extract.assert_called_once()
        assert not Attachment.objects.filter(user=user).exists()

    @mock.patch('chat.views.scan_attachment', return_value=CLEAN)
    def test_deduplicated_uploads_are_each_scanned(self, scan, auth_client, settings):
        settings.ATTACHMENT_MALWARE_SCAN_REQUIRED = True
        first = auth_client.post(
            '/api/attachments/upload/', {'file': _img_upload('one.png')}, format='multipart',
        )
        second = auth_client.post(
            '/api/attachments/upload/', {'file': _img_upload('two.png')}, format='multipart',
        )

        assert first.status_code == 201
        assert second.status_code == 200
        assert second.json()['deduplicated'] is True
        assert scan.call_count == 2


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
class TestUploadAttempts:
    def test_replaying_an_attempt_returns_the_same_attachment(self, auth_client, user):
        attempt_id = uuid.uuid4()
        first = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload(), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )
        replay = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload('replay.png'), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )

        assert first.status_code == 201
        assert replay.status_code == 200
        assert replay.json()['id'] == first.json()['id']
        assert replay.json()['replayed'] is True
        assert Attachment.objects.filter(user=user).count() == 1

    def test_cancel_after_commit_removes_the_attempts_new_attachment(self, auth_client, user):
        attempt_id = uuid.uuid4()
        uploaded = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload(), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )

        canceled = auth_client.delete(f'/api/attachments/upload/{attempt_id}/')

        assert uploaded.status_code == 201
        assert canceled.status_code == 204
        assert not Attachment.objects.filter(pk=uploaded.json()['id']).exists()
        attempt = AttachmentUploadAttempt.objects.get(pk=attempt_id)
        assert attempt.state == AttachmentUploadAttempt.STATE_CANCELED
        assert attempt.attachment_id is None
        assert attempt.owns_attachment is False

    def test_cancel_before_commit_blocks_a_late_upload(self, auth_client, user):
        attempt_id = uuid.uuid4()

        assert auth_client.delete(f'/api/attachments/upload/{attempt_id}/').status_code == 204
        uploaded = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload(), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )

        assert uploaded.status_code == 409
        assert uploaded.json()['code'] == 'upload_canceled'
        assert not Attachment.objects.filter(user=user).exists()

    def test_canceling_a_deduplicated_attempt_keeps_the_older_file(self, auth_client, user):
        original = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload()},
            format='multipart',
        )
        attempt_id = uuid.uuid4()
        duplicate = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload('duplicate.png'), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )

        assert duplicate.status_code == 200
        assert duplicate.json()['id'] == original.json()['id']
        assert duplicate.json()['deduplicated'] is True
        assert auth_client.delete(f'/api/attachments/upload/{attempt_id}/').status_code == 204
        assert Attachment.objects.filter(pk=original.json()['id'], user=user).exists()

    def test_attempt_ids_are_owner_scoped(self, auth_client, other_client, user):
        attempt_id = uuid.uuid4()
        uploaded = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload(), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )

        assert other_client.delete(f'/api/attachments/upload/{attempt_id}/').status_code == 404
        collision = other_client.post(
            '/api/attachments/upload/',
            {'file': _txt_upload(), 'upload_attempt_id': str(attempt_id)},
            format='multipart',
        )

        assert collision.status_code == 409
        assert collision.json()['code'] == 'invalid_upload_attempt'
        assert Attachment.objects.filter(pk=uploaded.json()['id'], user=user).exists()

    @pytest.mark.parametrize('attempt_id', ['not-a-uuid', '00000000000000000000000000000000'])
    def test_upload_rejects_noncanonical_attempt_ids(self, auth_client, attempt_id):
        response = auth_client.post(
            '/api/attachments/upload/',
            {'file': _img_upload(), 'upload_attempt_id': attempt_id},
            format='multipart',
        )

        assert response.status_code == 400


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

    def _create_files(self, user, count, kind=Attachment.KIND_IMAGE):
        return [
            Attachment.objects.create(
                user=user,
                file=f'attachments/test/{index}.png',
                original_name=f'file-{index}.png',
                mime_type='image/png',
                size=10,
                kind=kind,
            )
            for index in range(count)
        ]

    def test_signed_cursor_paginates_attachments(self, auth_client, user):
        files = self._create_files(user, 7)
        first = auth_client.get('/api/attachments/?include_count=1&limit=3').json()
        second = auth_client.get(
            f'/api/attachments/?include_count=1&limit=3&cursor={first["next_cursor"]}',
        ).json()
        third = auth_client.get(
            f'/api/attachments/?include_count=1&limit=3&cursor={second["next_cursor"]}',
        ).json()

        returned = [*first['results'], *second['results'], *third['results']]
        expected = list(
            Attachment.objects.filter(user=user)
            .order_by('-created_at', '-id')
            .values_list('id', flat=True)
        )
        assert [item['id'] for item in returned] == expected
        assert len({item['id'] for item in returned}) == len(files)
        assert first['count'] == 7
        assert third['next_cursor'] is None

    def test_attachment_cursor_is_owner_and_kind_bound(
        self, auth_client, other_client, user, other_user,
    ):
        self._create_files(user, 2)
        self._create_files(other_user, 2)
        cursor = auth_client.get(
            '/api/attachments/?include_count=1&limit=1&kind=image',
        ).json()['next_cursor']

        assert other_client.get(
            f'/api/attachments/?include_count=1&limit=1&kind=image&cursor={cursor}',
        ).status_code == 400
        assert auth_client.get(
            f'/api/attachments/?include_count=1&limit=1&kind=document&cursor={cursor}',
        ).status_code == 400
        assert auth_client.get(
            f'/api/attachments/?include_count=1&limit=1&kind=image&cursor={cursor}x',
        ).status_code == 400

    def test_attachment_list_rejects_invalid_bounds(self, auth_client):
        for limit in ('0', '51', 'many'):
            assert auth_client.get(
                f'/api/attachments/?include_count=1&limit={limit}',
            ).status_code == 400
        assert auth_client.get('/api/attachments/?kind=private').status_code == 400
        assert auth_client.get('/api/attachments/?cursor=unsigned').status_code == 400

    def test_legacy_attachment_list_is_bounded(self, auth_client, user):
        self._create_files(user, 105)

        body = auth_client.get('/api/attachments/').json()

        assert isinstance(body, list)
        assert len(body) == 100


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


@pytest.mark.django_db(transaction=True)
def test_attachment_file_survives_database_delete_rollback(user):
    attachment = Attachment.objects.create(
        user=user,
        file=SimpleUploadedFile('rollback.txt', b'keep', content_type='text/plain'),
        original_name='rollback.txt',
        mime_type='text/plain',
        size=4,
        kind=Attachment.KIND_DOCUMENT,
    )
    attachment_id = attachment.pk
    attachment_path = attachment.file.path

    with pytest.raises(RuntimeError, match='force rollback'):
        with transaction.atomic():
            attachment.delete()
            raise RuntimeError('force rollback')

    assert Attachment.objects.filter(pk=attachment_id).exists()
    assert Path(attachment_path).exists()


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

    def test_content_fingerprint_is_keyed_owner_scoped_and_rewinds_upload(self, settings):
        upload = _img_upload()
        expected = hmac.new(
            settings.SECRET_KEY.encode(),
            b'attachment-dedup:v1:user:7\0' + _png_bytes(),
            hashlib.sha256,
        ).hexdigest()
        fingerprint = content_fingerprint(upload, 7)
        assert fingerprint == expected
        assert fingerprint != hashlib.sha256(_png_bytes()).hexdigest()
        assert upload.read() == _png_bytes()

        other_owner_upload = _img_upload()
        assert content_fingerprint(other_owner_upload, 8) != fingerprint


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
