"""Attachment type checks and resource-bounded document extraction."""
import hashlib
import hmac
import logging
import os
import socket
import struct
import subprocess
import sys
from pathlib import Path

from django.conf import settings

log = logging.getLogger(__name__)
EXTRACT_TIMEOUT_SECONDS = 8
PARSER_MAGIC = b'AIP1'
PARSER_REQUEST = struct.Struct('!4sBII')
PARSER_RESPONSE = struct.Struct('!4sBI')
PARSER_STATUS_OK = 0
PARSER_STATUS_UNREADABLE = 1
PARSER_MAX_OUTPUT_BYTES = 200_000
DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
_EXT_TO_MIME = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.webp': 'image/webp', '.gif': 'image/gif', '.pdf': 'application/pdf',
    '.txt': 'text/plain', '.md': 'text/markdown', '.markdown': 'text/markdown',
    '.docx': DOCX_MIME,
}


def content_fingerprint(uploaded_file, owner_id) -> str:
    """Return a secret, owner-scoped upload fingerprint and rewind the file.

    Owner scoping prevents identical files from being correlated across accounts,
    while the keyed digest prevents offline confirmation from a leaked hash list.
    """
    domain = f'attachment-dedup:v1:user:{owner_id}\0'.encode()
    digest = hmac.new(settings.SECRET_KEY.encode(), domain, hashlib.sha256)
    uploaded_file.seek(0)
    for chunk in uploaded_file.chunks():
        digest.update(chunk)
    uploaded_file.seek(0)
    return digest.hexdigest()


def detect_mime(uploaded_file) -> str:
    """Require extension and content signature to agree; never trust HTTP MIME.

    Signature checks are not a malware scanner. Downloads are also authorized,
    non-executable and sandboxed, and complex parsing runs in a child process.
    """
    mime = _EXT_TO_MIME.get(Path(uploaded_file.name or '').suffix.lower())
    if not mime:
        return 'application/octet-stream'
    data = uploaded_file.read(settings.MAX_ATTACHMENT_SIZE + 1)
    uploaded_file.seek(0)
    valid = False
    if mime == 'image/png':
        valid = len(data) >= 33 and data.startswith(b'\x89PNG\r\n\x1a\n') and data[12:16] == b'IHDR'
    elif mime == 'image/jpeg':
        valid = len(data) >= 4 and data.startswith(b'\xff\xd8\xff')
    elif mime == 'image/gif':
        valid = len(data) >= 13 and data[:6] in (b'GIF87a', b'GIF89a')
    elif mime == 'image/webp':
        valid = len(data) >= 16 and data[:4] == b'RIFF' and data[8:12] == b'WEBP'
    elif mime == 'application/pdf':
        valid = data.startswith(b'%PDF-')
    elif mime in {'text/plain', 'text/markdown'}:
        try:
            data.decode('utf-8')
            valid = b'\x00' not in data
        except UnicodeDecodeError:
            pass
    elif mime == DOCX_MIME:
        # Complex ZIP/XML handling belongs to the isolated parser service.
        valid = len(data) >= 4 and data.startswith(b'PK\x03\x04')
    return mime if valid else 'application/octet-stream'


def kind_for_mime(mime: str) -> str | None:
    if mime in settings.ALLOWED_IMAGE_MIMES:
        return 'image'
    if mime in settings.ALLOWED_DOC_MIMES:
        return 'document'
    return None


class DocumentParserError(RuntimeError):
    """The isolated parser did not return an authoritative response."""


def _read_exact(client, length):
    data = bytearray()
    while len(data) < length:
        chunk = client.recv(length - len(data))
        if not chunk:
            raise DocumentParserError('document parser returned a truncated response')
        data.extend(chunk)
    return bytes(data)


def _remote_extract(data, mime, cap):
    kind = 1 if mime == 'application/pdf' else 2
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(settings.DOCUMENT_PARSER_TIMEOUT_SECONDS)
            client.connect(settings.DOCUMENT_PARSER_SOCKET)
            client.sendall(PARSER_REQUEST.pack(PARSER_MAGIC, kind, cap, len(data)))
            client.sendall(data)
            magic, status, length = PARSER_RESPONSE.unpack(
                _read_exact(client, PARSER_RESPONSE.size),
            )
            if magic != PARSER_MAGIC or length > min(PARSER_MAX_OUTPUT_BYTES, cap * 4):
                raise DocumentParserError('document parser returned an invalid response')
            payload = _read_exact(client, length)
            if client.recv(1):
                raise DocumentParserError('document parser returned trailing data')
        if status == PARSER_STATUS_UNREADABLE and not payload:
            return ''
        if status != PARSER_STATUS_OK:
            raise DocumentParserError('document parser returned an invalid status')
        return payload.decode('utf-8')[:cap]
    except DocumentParserError:
        raise
    except (OSError, UnicodeError, ValueError, struct.error) as exc:
        raise DocumentParserError('document parser is unavailable') from exc


def _local_extract(data, mime, cap):
    try:
        result = subprocess.run(
            [
                sys.executable,
                '-I',
                str(Path(__file__).with_name('document_worker.py')),
                'pdf' if mime == 'application/pdf' else 'docx',
                str(cap),
            ],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=EXTRACT_TIMEOUT_SECONDS,
            check=False,
            env={
                'PATH': os.defpath,
                'LANG': 'C.UTF-8',
                'PYTHONDONTWRITEBYTECODE': '1',
            },
        )
    except (subprocess.TimeoutExpired, OSError):
        log.warning('Document extraction timed out or could not start (type=%s)', mime)
        return ''
    if result.returncode == 0:
        return result.stdout.decode('utf-8', errors='replace')[:cap]
    log.warning('Document extraction failed (exit=%s, type=%s)', result.returncode, mime)
    return ''


def extract_text(uploaded_file, mime: str) -> str:
    cap = settings.DOC_EXTRACT_MAX_CHARS
    if mime in {'text/plain', 'text/markdown'}:
        data = uploaded_file.read(cap * 4)
        uploaded_file.seek(0)
        return data.decode('utf-8', errors='replace')[:cap]
    if mime not in {'application/pdf', DOCX_MIME}:
        return ''
    data = uploaded_file.read(settings.MAX_ATTACHMENT_SIZE + 1)
    uploaded_file.seek(0)
    if len(data) > settings.MAX_ATTACHMENT_SIZE:
        return ''
    if settings.DOCUMENT_PARSER_REQUIRED:
        return _remote_extract(data, mime, cap)
    return _local_extract(data, mime, cap)
