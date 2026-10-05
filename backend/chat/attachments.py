"""Attachment type checks and resource-bounded document extraction."""
import io
import logging
import os
from pathlib import Path
import subprocess
import sys
import zipfile

from django.conf import settings

log = logging.getLogger(__name__)
EXTRACT_TIMEOUT_SECONDS = 8
DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
_EXT_TO_MIME = {
    '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
    '.webp': 'image/webp', '.gif': 'image/gif', '.pdf': 'application/pdf',
    '.txt': 'text/plain', '.md': 'text/markdown', '.markdown': 'text/markdown',
    '.docx': DOCX_MIME,
}


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
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                entries = archive.infolist()
                names = {entry.filename for entry in entries}
                valid = (
                    {'[Content_Types].xml', 'word/document.xml'} <= names
                    and len(entries) <= 1000
                    and sum(entry.file_size for entry in entries) <= 32 * 1024 * 1024
                    and all(not entry.flag_bits & 1 and entry.file_size <= 16 * 1024 * 1024
                            and entry.file_size <= max(entry.compress_size, 1) * 200
                            for entry in entries)
                )
        except (zipfile.BadZipFile, ValueError):
            pass
    return mime if valid else 'application/octet-stream'


def kind_for_mime(mime: str) -> str | None:
    if mime in settings.ALLOWED_IMAGE_MIMES:
        return 'image'
    if mime in settings.ALLOWED_DOC_MIMES:
        return 'document'
    return None


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
    try:
        result = subprocess.run(
            [sys.executable, '-I', str(Path(__file__).with_name('document_worker.py')),
             'pdf' if mime == 'application/pdf' else 'docx', str(cap)],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=EXTRACT_TIMEOUT_SECONDS, check=False,
            env={'PATH': os.defpath, 'LANG': 'C.UTF-8'},
        )
        if result.returncode == 0:
            return result.stdout.decode('utf-8', errors='replace')[:cap]
        log.warning('Document extraction failed (exit=%s, type=%s)', result.returncode, mime)
    except (subprocess.TimeoutExpired, OSError):
        log.warning('Document extraction timed out or could not start (type=%s)', mime)
    return ''
