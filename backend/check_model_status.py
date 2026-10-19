#!/usr/bin/env python3
"""Credential-free health gate for the signed runtime model status."""
import os


def main():
    os.environ.setdefault(
        'DJANGO_SETTINGS_MODULE',
        'nvidia_chat.model_status_check_settings',
    )
    import django

    django.setup()
    from chat.model_status import get_status

    state = get_status().get('state')
    if state not in {'verified', 'degraded'}:
        raise SystemExit('model status failed independent verification')
    print(f'model_status={state}')


if __name__ == '__main__':
    main()
