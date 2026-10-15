import logging

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from chat.models import TwoFactor
from chat.twofactor import (
    TwoFactorKeyError,
    _active_key_id,
    _decrypt_secret,
    _encrypt_secret,
    _secret_key_id,
)

security_log = logging.getLogger('security')


class Command(BaseCommand):
    help = 'Re-encrypt every TOTP secret with the configured active 2FA key.'

    def handle(self, *args, **options):
        active = _active_key_id()
        rotated = 0
        already_active = 0
        try:
            with transaction.atomic():
                factors = TwoFactor.objects.select_for_update().only('pk', 'secret').order_by('pk')
                for factor in factors:
                    plain = _decrypt_secret(factor.secret)
                    if _secret_key_id(factor.secret) == active:
                        already_active += 1
                        continue
                    factor.secret = _encrypt_secret(plain)
                    factor.save(update_fields=['secret'])
                    rotated += 1
        except (TwoFactorKeyError, TypeError, ValueError) as exc:
            raise CommandError(
                '2FA key rotation aborted; no secrets were changed because an artifact failed validation.',
            ) from exc

        security_log.warning(
            'event=two_factor_keys_rotated active_key_id=%s rotated=%s unchanged=%s',
            settings.TWO_FACTOR_ACTIVE_KEY_ID,
            rotated,
            already_active,
        )
        self.stdout.write(self.style.SUCCESS(
            f'2FA key rotation complete: rotated={rotated} unchanged={already_active} '
            f'active_key_id={active}. Recovery hashes retain their recorded key IDs.',
        ))
