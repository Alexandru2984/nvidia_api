"""Django authentication backend that defers password-hash mutation."""

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .passwords import burn_default_password_hasher, verify_password_without_upgrade


class DeferredPasswordUpgradeBackend(ModelBackend):
    """Authenticate normally but let the completed 2FA flow apply upgrades."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        if username is None or password is None:
            return None
        try:
            user = UserModel._default_manager.get_by_natural_key(username)
        except UserModel.DoesNotExist:
            burn_default_password_hasher(password)
            return None

        valid, needs_upgrade = verify_password_without_upgrade(password, user.password)
        if not valid or not self.user_can_authenticate(user):
            return None
        user._password_hash_needs_upgrade = needs_upgrade
        return user
