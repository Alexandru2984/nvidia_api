from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from chat.models import RegistrationInvite
from chat.registration import generate_invite_code, hash_invite_code


class Command(BaseCommand):
    help = 'Create a one-time registration invite and print its plaintext code once.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--expires-hours',
            type=int,
            default=72,
            help='Invite lifetime in hours (1-720; default 72).',
        )

    def handle(self, *args, **options):
        hours = options['expires_hours']
        if not 1 <= hours <= 720:
            raise CommandError('--expires-hours must be between 1 and 720')

        code = generate_invite_code()
        expires_at = timezone.now() + timedelta(hours=hours)
        invite = RegistrationInvite.objects.create(
            code_hash=hash_invite_code(code),
            expires_at=expires_at,
        )
        self.stdout.write(f'Invitation id: {invite.pk}')
        self.stdout.write(f'Invitation code (shown once): {code}')
        self.stdout.write(f'Expires at: {expires_at.isoformat()}')
