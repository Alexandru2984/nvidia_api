"""Generation and verification primitives for one-time registration invites."""
import hashlib
import hmac
import secrets

from django.conf import settings

INVITE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
INVITE_LENGTH = 20


def generate_invite_code():
    raw = ''.join(secrets.choice(INVITE_ALPHABET) for _ in range(INVITE_LENGTH))
    return '-'.join(raw[index:index + 4] for index in range(0, INVITE_LENGTH, 4))


def normalize_invite_code(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    normalized = value.replace('-', '').replace(' ', '').upper()
    if len(normalized) != INVITE_LENGTH:
        return None
    if any(character not in INVITE_ALPHABET for character in normalized):
        return None
    return normalized


def hash_invite_code(value):
    normalized = normalize_invite_code(value)
    if normalized is None:
        return None
    message = f'registration-invite-v1:{normalized}'.encode()
    return hmac.new(settings.SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()
