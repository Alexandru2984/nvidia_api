#!/usr/bin/env python3
"""Run the model probe with the credential-minimal isolated settings module."""
import os
import sys


def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'nvidia_chat.probe_settings')
    import django

    django.setup()
    from chat.management.commands.probe_models import Command

    Command().run_from_argv([sys.argv[0], 'probe_models', *sys.argv[1:]])


if __name__ == '__main__':
    main()
