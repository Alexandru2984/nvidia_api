"""Helpers for attachments: validation, MIME sniffing, document text extraction."""
import io
import logging
import mimetypes
import signal
from contextlib import contextmanager

from django.conf import settings

log = logging.getLogger(__name__)

# Caps applied during text extraction. These are independent of MAX_ATTACHMENT_SIZE
# (10MB) — a 10MB PDF can still take many seconds to parse, or unzip into much
# more text than that. The caps below are the worst case we'll burn on parsing.
EXTRACT_TIMEOUT_SECONDS = 8
PDF_MAX_PAGES = 200
DOCX_MAX_PARAGRAPHS = 5000


@contextmanager
def _time_budget(seconds):
    """SIGALRM-based timeout. Only works on the main thread; gthread workers run
    requests on worker threads, so we install a thread-local fallback flag."""
    def _handler(signum, frame):  # pragma: no cover
        raise TimeoutError(f'document extraction exceeded {seconds}s')

    try:
        old = signal.signal(signal.SIGALRM, _handler)
        signal.alarm(seconds)
        installed = True
    except (ValueError, AttributeError):
        # Not on main thread — fall through; per-page/paragraph caps still apply.
        installed = False
    try:
        yield
    finally:
        if installed:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)


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
    """Best-effort text extraction; returns empty string on failure or timeout."""
    cap = settings.DOC_EXTRACT_MAX_CHARS
    try:
        with _time_budget(EXTRACT_TIMEOUT_SECONDS):
            if mime == 'application/pdf':
                return _extract_pdf(uploaded_file, cap)
            if mime == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                return _extract_docx(uploaded_file, cap)
            if mime in {'text/plain', 'text/markdown'}:
                # Read at most `cap` bytes — text files larger than that are
                # almost certainly logs/dumps and we only feed `cap` chars to
                # the model anyway.
                data = uploaded_file.read(cap + 1)
                uploaded_file.seek(0)
                return data.decode('utf-8', errors='replace')[:cap]
    except TimeoutError:
        log.warning('Extraction timed out for %s (%s)', uploaded_file.name, mime)
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
    for i, page in enumerate(reader.pages):
        if i >= PDF_MAX_PAGES:
            break
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
    parts = []
    total = 0
    for i, p in enumerate(doc.paragraphs):
        if i >= DOCX_MAX_PARAGRAPHS:
            break
        if not p.text:
            continue
        parts.append(p.text)
        total += len(p.text)
        if total >= cap:
            break
    return '\n'.join(parts)[:cap]
