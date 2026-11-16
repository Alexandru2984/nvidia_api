from django.core.management.base import BaseCommand, CommandError

from chat.auth_mail import AuthMailUnavailable, check_auth_mail_budget


class Command(BaseCommand):
    help = 'Validate the private durable SMTP budget without sending email.'

    def handle(self, *args, **options):
        try:
            check_auth_mail_budget()
        except AuthMailUnavailable:
            raise CommandError('Authentication mail budget is unavailable.') from None
        self.stdout.write('Authentication mail budget is ready; no delivery attempted.')
