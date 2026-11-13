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
_JPEG_START_OF_FRAME_MARKERS = frozenset({
    0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
    0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF,
})


def _jpeg_dimensions(data):
    if len(data) < 4 or not data.startswith(b'\xff\xd8'):
        return None
    offset = 2
    while offset < len(data):
        if data[offset] != 0xFF:
            return None
        while offset < len(data) and data[offset] == 0xFF:
            offset += 1
        if offset >= len(data):
            return None
        marker = data[offset]
        offset += 1
        if marker in {0x01, *range(0xD0, 0xD9)}:
            continue
        if marker in {0xD9, 0xDA} or offset + 2 > len(data):
            return None
        segment_length = int.from_bytes(data[offset:offset + 2], 'big')
        if segment_length < 2 or offset + segment_length > len(data):
            return None
        if marker in _JPEG_START_OF_FRAME_MARKERS:
            if segment_length < 11:
                return None
            height = int.from_bytes(data[offset + 3:offset + 5], 'big')
            width = int.from_bytes(data[offset + 5:offset + 7], 'big')
            components = data[offset + 7]
            if not 1 <= components <= 4 or segment_length != 8 + 3 * components:
                return None
            return width, height
        offset += segment_length
    return None


def _webp_dimensions(data):
    if (
        len(data) < 20
        or data[:4] != b'RIFF'
        or data[8:12] != b'WEBP'
        or int.from_bytes(data[4:8], 'little') + 8 > len(data)
    ):
        return None
    limit = int.from_bytes(data[4:8], 'little') + 8
    offset = 12
    while offset + 8 <= limit:
        kind = data[offset:offset + 4]
        length = int.from_bytes(data[offset + 4:offset + 8], 'little')
        payload = offset + 8
        end = payload + length
        if end > limit or end > len(data):
            return None
        if kind == b'VP8X':
            if length < 10:
                return None
            width = 1 + int.from_bytes(data[payload + 4:payload + 7], 'little')
            height = 1 + int.from_bytes(data[payload + 7:payload + 10], 'little')
            return width, height
        if kind == b'VP8 ':
            if length < 10 or data[payload + 3:payload + 6] != b'\x9d\x01\x2a':
                return None
            width = int.from_bytes(data[payload + 6:payload + 8], 'little') & 0x3FFF
            height = int.from_bytes(data[payload + 8:payload + 10], 'little') & 0x3FFF
            return width, height
        if kind == b'VP8L':
            if length < 5 or data[payload] != 0x2F:
                return None
            bits = int.from_bytes(data[payload + 1:payload + 5], 'little')
            width = 1 + (bits & 0x3FFF)
            height = 1 + ((bits >> 14) & 0x3FFF)
            return width, height
        offset = end + (length & 1)
    return None


def image_dimensions(data, mime):
    """Read bounded raster dimensions without invoking an image decoder."""
    if not isinstance(data, (bytes, bytearray)):
        return None
    if mime == 'image/png':
        if (
            len(data) < 33
            or not data.startswith(b'\x89PNG\r\n\x1a\n')
            or data[8:16] != b'\x00\x00\x00\rIHDR'
        ):
            return None
        return struct.unpack('>II', data[16:24])
    if mime == 'image/jpeg':
        return _jpeg_dimensions(data)
    if mime == 'image/gif':
        if len(data) < 13 or data[:6] not in (b'GIF87a', b'GIF89a'):
            return None
        return struct.unpack('<HH', data[6:10])
    if mime == 'image/webp':
        return _webp_dimensions(data)
    return None


def image_within_limits(data, mime):
    dimensions = image_dimensions(data, mime)
    if dimensions is None:
        return False
    width, height = dimensions
    return (
        1 <= width <= settings.MAX_IMAGE_DIMENSION
        and 1 <= height <= settings.MAX_IMAGE_DIMENSION
        and width * height <= settings.MAX_IMAGE_PIXELS
    )


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
    if mime in settings.ALLOWED_IMAGE_MIMES:
        valid = image_within_limits(data, mime)
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
