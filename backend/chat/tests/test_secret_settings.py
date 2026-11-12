import os
import re
import subprocess
import sys

import pytest
from django.core.exceptions import ImproperlyConfigured

from nvidia_chat.secret_settings import secret_setting


@pytest.fixture(autouse=True)
def clean_secret_environment(monkeypatch):
    for name in ('APP_TEST_SECRET', 'APP_TEST_SECRET_FILE'):
        monkeypatch.delenv(name, raising=False)


def test_reads_direct_environment_value(monkeypatch):
    monkeypatch.setenv('APP_TEST_SECRET', 'direct-value')

    assert secret_setting('APP_TEST_SECRET') == 'direct-value'


def test_reads_canonical_regular_file_and_removes_one_terminal_newline(monkeypatch, tmp_path):
    source = tmp_path / 'credential'
    source.write_bytes(b'file-value\n')
    monkeypatch.setenv('APP_TEST_SECRET_FILE', str(source))

    assert secret_setting('APP_TEST_SECRET') == 'file-value'


def test_rejects_ambiguous_sources_without_disclosing_values(monkeypatch, tmp_path):
    source = tmp_path / 'credential'
    source.write_text('file-value', encoding='utf-8')
    monkeypatch.setenv('APP_TEST_SECRET', 'direct-value')
    monkeypatch.setenv('APP_TEST_SECRET_FILE', str(source))

    with pytest.raises(ImproperlyConfigured) as caught:
        secret_setting('APP_TEST_SECRET')

    message = str(caught.value)
    assert 'direct-value' not in message
    assert 'file-value' not in message
    assert str(tmp_path) not in message


@pytest.mark.parametrize('payload', [b'', b'line-one\nline-two', b'bad\x00value', b'\xff'])
def test_rejects_empty_control_or_non_utf8_file_content(monkeypatch, tmp_path, payload):
    source = tmp_path / 'credential'
    source.write_bytes(payload)
    monkeypatch.setenv('APP_TEST_SECRET_FILE', str(source))

    with pytest.raises(ImproperlyConfigured):
        secret_setting('APP_TEST_SECRET')


def test_rejects_relative_symlink_and_oversized_files(monkeypatch, tmp_path):
    source = tmp_path / 'credential'
    source.write_text('safe', encoding='utf-8')
    link = tmp_path / 'credential-link'
    link.symlink_to(source)

    for candidate in ('relative/credential', str(link)):
        monkeypatch.setenv('APP_TEST_SECRET_FILE', candidate)
        with pytest.raises(ImproperlyConfigured):
            secret_setting('APP_TEST_SECRET')

    source.write_bytes(b'x' * 17)
    monkeypatch.setenv('APP_TEST_SECRET_FILE', str(source))
    with pytest.raises(ImproperlyConfigured):
        secret_setting('APP_TEST_SECRET', max_bytes=16)


def test_missing_required_and_optional_values_are_explicit(monkeypatch):
    with pytest.raises(ImproperlyConfigured, match='APP_TEST_SECRET_FILE must be set'):
        secret_setting('APP_TEST_SECRET')

    assert secret_setting('APP_TEST_SECRET', required=False, default='') == ''


def test_production_settings_resolve_every_secret_through_loader():
    settings_source = (
        __import__('pathlib').Path(__file__).parents[2] / 'nvidia_chat' / 'settings.py'
    ).read_text(encoding='utf-8')

    for name in (
        'DJANGO_SECRET_KEY',
        'DB_PASSWORD',
        'NVIDIA_API_KEY',
        'SMTP_PASS',
        'TWO_FACTOR_KEYS',
        'ADMIN_AUDIT_KEYS',
    ):
        assert re.search(
            rf"secret_setting\(\s*'{name}'",
            settings_source,
        ) or name in {
            'TWO_FACTOR_KEYS', 'ADMIN_AUDIT_KEYS',
        }
    assert "secret_setting(keys_name" in settings_source
    assert "os.environ['DB_PASSWORD']" not in settings_source
    assert "os.environ['NVIDIA_API_KEY']" not in settings_source


def test_production_settings_boot_entirely_from_secret_files(tmp_path):
    credentials = {
        'DJANGO_SECRET_KEY': 'file-signing-secret',
        'DB_PASSWORD': 'file-database-secret',
        'NVIDIA_API_KEY': 'file-provider-secret',
        'SMTP_PASS': 'file-mail-secret',
        'TWO_FACTOR_KEYS': '{"test":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}',
        'ADMIN_AUDIT_KEYS': '{"audit":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}',
    }
    environment = os.environ.copy()
    for name, value in credentials.items():
        environment.pop(name, None)
        source = tmp_path / name.lower()
        source.write_text(value, encoding='utf-8')
        environment[f'{name}_FILE'] = str(source)
    environment.update({
        'AICHAT_RUNTIME_DIR': str(tmp_path),
        'DJANGO_DEBUG': 'False',
        'DB_NAME': 'fixture',
        'DB_USER': 'fixture',
        'TWO_FACTOR_ACTIVE_KEY_ID': 'test',
        'TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED': 'false',
        'ADMIN_AUDIT_ACTIVE_KEY_ID': 'audit',
        'ADMIN_AUDIT_LEGACY_SECRET_KEY_ENABLED': 'false',
    })

    result = subprocess.run(
        [
            sys.executable,
            '-c',
            'from nvidia_chat import settings; '
            'assert settings.SECRET_KEY; '
            'assert settings.DATABASES["default"]["PASSWORD"]; '
            'assert settings.NVIDIA_API_KEY; '
            'assert settings.EMAIL_HOST_PASSWORD; '
            'assert settings.TWO_FACTOR_ACTIVE_KEY_ID == "test"; '
            'assert settings.ADMIN_AUDIT_ACTIVE_KEY_ID == "audit"',
        ],
        cwd=__import__('pathlib').Path(__file__).parents[2],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 0, result.stderr
