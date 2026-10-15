import io

from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand, CommandError

from chat.attachments import DOCX_MIME, DocumentParserError, extract_text


class Command(BaseCommand):
    help = 'Verify isolated document-parser connectivity and real DOCX extraction.'

    def handle(self, *args, **options):
        from docx import Document

        marker = 'AI Chat Hub isolated parser readiness marker'
        document = Document()
        document.add_paragraph(marker)
        content = io.BytesIO()
        document.save(content)
        upload = SimpleUploadedFile('readiness.docx', content.getvalue())
        try:
            extracted = extract_text(upload, DOCX_MIME)
        except DocumentParserError as exc:
            raise CommandError(str(exc)) from None
        if marker not in extracted:
            raise CommandError('document parser readiness extraction was unexpected')
        self.stdout.write(self.style.SUCCESS('Isolated document parser is ready.'))
