from django.apps import AppConfig


class ChatConfig(AppConfig):
    name = 'chat'

    def ready(self):
        # Register authentication and privileged-change security receivers.
        from . import (  # noqa: F401
            admin_audit,
            security_events,
        )
