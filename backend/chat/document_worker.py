"""Linux parser worker: no Django import, credentials or unbounded runtime.

This limits resource consumption, not filesystem privileges. The service's
systemd sandbox provides the filesystem boundary for this child as well.
"""
import io
import resource
import sys


def main():
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (6, 7))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    kind, cap = sys.argv[1], min(int(sys.argv[2]), 50_000)
    data = sys.stdin.buffer.read(10 * 1024 * 1024 + 1)
    if len(data) > 10 * 1024 * 1024:
        return 1
    if kind == 'pdf':
        from pypdf import PdfReader
        document = PdfReader(io.BytesIO(data))
        texts = ((page.extract_text() or '') for page in document.pages[:200])
    elif kind == 'docx':
        from docx import Document
        document = Document(io.BytesIO(data))
        texts = (paragraph.text for paragraph in document.paragraphs[:5000])
    else:
        return 1
    remaining = cap
    for text in texts:
        chunk = (text + '\n\n')[:remaining]
        sys.stdout.buffer.write(chunk.encode('utf-8'))
        remaining -= len(chunk)
        if remaining <= 0:
            break
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
