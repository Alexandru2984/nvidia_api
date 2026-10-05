import io
import subprocess
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile

from chat.attachments import extract_text

pytestmark = pytest.mark.django_db


def test_private_download_owner_only(auth_client, other_client, client):
    result = auth_client.post('/api/attachments/upload/', {
        'file': SimpleUploadedFile('private.txt', b'private content', content_type='text/plain'),
    }, format='multipart')
    url = result.json()['url']
    assert url.startswith('/api/attachments/')
    assert other_client.get(url).status_code == 404
    owner_response = auth_client.get(url)
    assert b''.join(owner_response.streaming_content) == b'private content'
    assert 'attachment;' in owner_response['Content-Disposition']
    assert 'no-store' in owner_response['Cache-Control']
    assert 'sandbox' in owner_response['Content-Security-Policy']
    auth_client.logout()
    assert client.get(url).status_code == 403


@pytest.mark.parametrize('name,content,mime', [
    ('payload.html', b'<script>alert(1)</script>', 'image/png'),
    ('payload.svg', b'<svg onload="alert(1)"></svg>', 'image/png'),
    ('payload.png', b'<script>alert(1)</script>', 'image/png'),
    ('payload.pdf', b'not a PDF', 'application/pdf'),
    ('payload.txt', b'MZ\x00binary', 'text/plain'),
    ('payload.docx', b'not a ZIP', 'application/zip'),
])
def test_spoofed_upload_rejected(auth_client, name, content, mime):
    response = auth_client.post('/api/attachments/upload/', {
        'file': SimpleUploadedFile(name, content, content_type=mime),
    }, format='multipart')
    assert response.status_code == 415


def test_docx_zip_bomb_rejected(auth_client):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('[Content_Types].xml', '<xml/>')
        archive.writestr('word/document.xml', 'x' * 1_000_000)
    response = auth_client.post('/api/attachments/upload/', {
        'file': SimpleUploadedFile('bomb.docx', data.getvalue()),
    }, format='multipart')
    assert response.status_code == 415


def test_valid_docx_extracted_from_gunicorn_like_thread():
    from docx import Document
    doc = Document()
    doc.add_paragraph('Bounded extraction works')
    data = io.BytesIO()
    doc.save(data)
    upload = SimpleUploadedFile('test.docx', data.getvalue())
    with ThreadPoolExecutor(max_workers=1) as executor:
        output = executor.submit(extract_text, upload,
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document').result(timeout=12)
    assert 'Bounded extraction works' in output


def test_parser_timeout_is_handled_without_inheriting_secrets():
    with patch('chat.attachments.subprocess.run', side_effect=subprocess.TimeoutExpired('parser', 8)) as run:
        assert extract_text(SimpleUploadedFile('x.pdf', b'%PDF-1.7'), 'application/pdf') == ''
    assert run.call_args.kwargs['timeout'] == 8
    assert 'DJANGO_SECRET_KEY' not in run.call_args.kwargs['env']
