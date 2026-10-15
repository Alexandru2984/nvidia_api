from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError

from chat.malware import CLEAN, INFECTED, MalwareScanError, ping_scanner, scan_attachment


class Command(BaseCommand):
    help = 'Verify ClamAV connectivity plus benign and EICAR signature verdicts.'

    def handle(self, *args, **options):
        # Keep the standardized test signature non-contiguous in source so local
        # repository scanners do not quarantine this management command itself.
        eicar = (
            b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'
            b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        )
        try:
            ping_scanner()
            clean = scan_attachment(ContentFile(b'AI Chat Hub scanner readiness probe.'))
            detected = scan_attachment(ContentFile(eicar))
        except MalwareScanError as exc:
            raise CommandError(str(exc)) from None
        if clean != CLEAN or detected != INFECTED:
            raise CommandError('malware scanner readiness verdicts were unexpected')
        self.stdout.write(self.style.SUCCESS('Attachment malware scanner is ready.'))
