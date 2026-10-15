from collections import Counter

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from chat.models import TwoFactor
from chat.twofactor import (
    RECOVERY_DIGEST_RE,
    TwoFactorKeyError,
    _decrypt_secret,
    _parse_envelope,
    _root_key,
    _secret_key_id,
)


class Command(BaseCommand):
    help = 'Validate every stored 2FA artifact and report its key dependencies.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--require-active',
            action='store_true',
            help='Fail if any artifact does not use the active key.',
        )

    def handle(self, *args, **options):
        active = settings.TWO_FACTOR_ACTIVE_KEY_ID
        secret_keys = Counter()
        recovery_keys = Counter()
        invalid_secrets = 0
        invalid_recovery = 0

        for factor in TwoFactor.objects.only('secret', 'recovery_codes').iterator(chunk_size=200):
            try:
                _decrypt_secret(factor.secret)
                secret_keys[_secret_key_id(factor.secret) or 'legacy'] += 1
            except (TwoFactorKeyError, TypeError, ValueError):
                invalid_secrets += 1

            codes = factor.recovery_codes
            if not isinstance(codes, list):
                invalid_recovery += 1
                continue
            for stored in codes:
                try:
                    parsed = _parse_envelope(stored)
                    if parsed is None:
                        if (
                            not settings.TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED
                            or not RECOVERY_DIGEST_RE.fullmatch(stored)
                        ):
                            raise TwoFactorKeyError('invalid legacy recovery artifact')
                        recovery_keys['legacy'] += 1
                    else:
                        key_id, digest = parsed
                        if not RECOVERY_DIGEST_RE.fullmatch(digest):
                            raise TwoFactorKeyError('invalid recovery artifact')
                        _root_key(key_id)
                        recovery_keys[key_id] += 1
                except (TwoFactorKeyError, TypeError, ValueError):
                    invalid_recovery += 1

        self.stdout.write(
            '2FA key audit: '
            f'rows={sum(secret_keys.values()) + invalid_secrets} '
            f'secrets={dict(sorted(secret_keys.items()))} '
            f'recovery={dict(sorted(recovery_keys.items()))} '
            f'invalid_secrets={invalid_secrets} invalid_recovery={invalid_recovery}'
        )
        if invalid_secrets or invalid_recovery:
            raise CommandError('Stored 2FA artifacts failed validation.')
        if options['require_active']:
            inactive = (
                set(secret_keys).difference({active})
                | set(recovery_keys).difference({active})
            )
            if inactive:
                raise CommandError(
                    'Stored 2FA artifacts still depend on a legacy or inactive key.',
                )
        self.stdout.write(self.style.SUCCESS(f'2FA key audit passed; active_key_id={active}'))
