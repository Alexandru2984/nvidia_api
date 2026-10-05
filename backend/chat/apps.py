from django.apps import AppConfig


class ChatConfig(AppConfig):
    name = 'chat'

    def ready(self):
        # Register authentication security-event receivers.
        from . import security_events  # noqa: F401
