"""Password verification helpers with explicit, post-2FA hash upgrades."""

from django.contrib.auth.hashers import make_password, verify_password


def verify_password_without_upgrade(raw_password, encoded_password):
    """Return ``(valid, needs_upgrade)`` without writing the user record."""
    return verify_password(raw_password, encoded_password)


def burn_default_password_hasher(raw_password):
    """Reduce the timing gap for an unknown username without retaining a hash."""
    make_password(raw_password)


def upgrade_password_hash(user, raw_password, needs_upgrade):
    """Apply a verified lazy upgrade without treating it as a password change."""
    if not needs_upgrade:
        return False
    user.set_password(raw_password)
    # Match AbstractBaseUser.check_password(): a format/work-factor upgrade is
    # not a user-initiated password change and must not trigger validators.
    user._password = None
    user.save(update_fields=['password'])
    return True
