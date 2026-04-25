"""Helpers for attachments: validation, MIME sniffing, document text extraction."""
import io
import logging
import mimetypes

from django.conf import settings

log = logging.getLogger(__name__)


# Some clients send a generic octet-stream; fall back to extension.
_EXT_TO_MIME = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.gif': 'image/gif',
    '.pdf': 'application/pdf',
    '.txt': 'text/plain',
    '.md': 'text/markdown',
    '.markdown': 'text/markdown',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
}


def detect_mime(uploaded_file) -> str:
    declared = (uploaded_file.content_type or '').lower().split(';')[0].strip()
    if declared in settings.ALLOWED_UPLOAD_MIMES:
        return declared
    name = (uploaded_file.name or '').lower()
    for ext, mime in _EXT_TO_MIME.items():
        if name.endswith(ext):
            return mime
    guessed, _ = mimetypes.guess_type(name)
    return guessed or declared or 'application/octet-stream'


def kind_for_mime(mime: str) -> str | None:
    if mime in settings.ALLOWED_IMAGE_MIMES:
        return 'image'
    if mime in settings.ALLOWED_DOC_MIMES:
        return 'document'
    return None


def extract_text(uploaded_file, mime: str) -> str:
    """Best-effort text extraction; returns empty string on failure."""
    cap = settings.DOC_EXTRACT_MAX_CHARS
    try:
        if mime == 'application/pdf':
            return _extract_pdf(uploaded_file, cap)
        if mime == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            return _extract_docx(uploaded_file, cap)
        if mime in {'text/plain', 'text/markdown'}:
            data = uploaded_file.read()
            uploaded_file.seek(0)
            return data.decode('utf-8', errors='replace')[:cap]
    except Exception:
        log.exception('Failed to extract text from %s (%s)', uploaded_file.name, mime)
    return ''


def _extract_pdf(uploaded_file, cap: int) -> str:
    from pypdf import PdfReader
    data = uploaded_file.read()
    uploaded_file.seek(0)
    reader = PdfReader(io.BytesIO(data))
    out = []
    total = 0
    for page in reader.pages:
        try:
            t = page.extract_text() or ''
        except Exception:
            t = ''
        if not t:
            continue
        out.append(t)
        total += len(t)
        if total >= cap:
            break
    return '\n\n'.join(out)[:cap]


def _extract_docx(uploaded_file, cap: int) -> str:
    from docx import Document
    data = uploaded_file.read()
    uploaded_file.seek(0)
    doc = Document(io.BytesIO(data))
    parts = [p.text for p in doc.paragraphs if p.text]
    return '\n'.join(parts)[:cap]
