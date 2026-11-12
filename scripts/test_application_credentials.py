#!/usr/bin/env python3
"""Regressions for the root-managed application credential migration."""

import importlib.util
import os
import pwd
import grp
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


credentials = load_module(
    'check_application_credentials', ROOT / 'scripts/check_application_credentials.py',
)
database_config = load_module(
    'read_database_config', ROOT / 'scripts/read_database_config.py',
)


INLINE_VALUES = {
    'DJANGO_SECRET_KEY': 'fixture-signing-secret',
    'TWO_FACTOR_KEYS': '{"fixture":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}',
    'ADMIN_AUDIT_KEYS': '{"fixture":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}',
    'DB_PASSWORD': 'fixture-database-secret',
    'NVIDIA_API_KEY': 'fixture-provider-secret',
    'SMTP_PASS': 'fixture-mail-secret',
}


class ApplicationCredentialTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.env = self.root / '.env'
        self.stage = self.root / 'stage'
        self.managed = self.root / 'managed'
        self.output = self.root / 'output.env'
        self.stage.mkdir()
        lines = [
            'DB_NAME=fixture_db',
            'DB_USER=fixture_user',
            'DB_HOST=127.0.0.1',
            'DB_PORT=5432',
        ]
        lines.extend(f'{name}={value}' for name, value in INLINE_VALUES.items())
        self.env.write_text('\n'.join(lines) + '\n', encoding='utf-8')

    def tearDown(self):
        self.temporary.cleanup()

    def stage_and_normalize(self):
        credentials.stage_credentials(self.env, self.stage, self.output, self.managed)
        self.stage.rename(self.managed)
        current_uid = os.getuid()
        current_gid = os.getgid()
        os.chown(self.output, current_uid, current_gid)
        self.output.chmod(0o640)
        os.chown(self.managed, current_uid, current_gid)
        self.managed.chmod(0o750)
        for path in self.managed.iterdir():
            os.chown(path, current_uid, current_gid)
            path.chmod(0o640)
        return (
            pwd.getpwuid(current_uid).pw_name,
            grp.getgrgid(current_gid).gr_name,
        )

    def test_stages_each_secret_without_leaving_inline_values(self):
        owner, group = self.stage_and_normalize()

        rendered = self.output.read_text(encoding='utf-8')
        for name, value in INLINE_VALUES.items():
            self.assertNotIn(value, rendered)
            self.assertIn(f'{name}_FILE={self.managed}/', rendered)
        self.assertEqual(
            {path.name for path in self.managed.iterdir()},
            set(credentials.SECRET_FILES.values()),
        )
        credentials.check_credentials(
            self.output, self.managed, owner, group, owner,
        )

    def test_rejects_missing_duplicate_or_control_bearing_inline_secret(self):
        original = self.env.read_text(encoding='utf-8')
        cases = (
            original.replace('SMTP_PASS=fixture-mail-secret\n', ''),
            original + 'SMTP_PASS=duplicate\n',
            original.replace(
                'SMTP_PASS=fixture-mail-secret',
                'SMTP_PASS="line-one\\nline-two"',
            ),
        )
        for index, content in enumerate(cases):
            with self.subTest(index=index):
                self.env.write_text(content, encoding='utf-8')
                with self.assertRaises(credentials.CredentialError):
                    credentials.stage_credentials(
                        self.env, self.stage, self.output, self.managed,
                    )
                for path in self.stage.iterdir():
                    path.unlink()
                if self.output.exists():
                    self.output.unlink()

    def test_checker_rejects_symlinks_and_unmanifested_entries(self):
        owner, group = self.stage_and_normalize()
        target = self.managed / 'smtp-password'
        target.unlink()
        target.symlink_to(self.managed / 'db-password')
        with self.assertRaises(credentials.CredentialError):
            credentials.check_credentials(
                self.output, self.managed, owner, group, owner,
            )
        target.unlink()
        target.write_text('fixture-mail-secret', encoding='utf-8')
        target.chmod(0o640)
        extra = self.managed / 'unexpected'
        extra.write_text('not-a-secret', encoding='utf-8')
        with self.assertRaises(credentials.CredentialError):
            credentials.check_credentials(
                self.output, self.managed, owner, group, owner,
            )

    def test_checker_accepts_only_the_exact_read_only_admin_acl(self):
        owner, group = self.stage_and_normalize()
        admin = 'nobody'
        self.root.chmod(0o750)
        subprocess.run(['setfacl', '-b', str(self.root), str(self.managed)], check=True)
        subprocess.run(['setfacl', '-m', f'u:{admin}:--x', str(self.root)], check=True)
        subprocess.run(['setfacl', '-m', f'u:{admin}:r-x', str(self.managed)], check=True)
        for path in self.managed.iterdir():
            subprocess.run(['setfacl', '-b', str(path)], check=True)
            subprocess.run(['setfacl', '-m', f'u:{admin}:r--', str(path)], check=True)

        credentials.check_credentials(
            self.output, self.managed, owner, group, owner, admin,
        )
        subprocess.run(
            ['setfacl', '-m', f'u:{admin}:rw-', str(self.managed / 'db-password')],
            check=True,
        )
        with self.assertRaises(credentials.CredentialError):
            credentials.check_credentials(
                self.output, self.managed, owner, group, owner, admin,
            )

    def test_database_reader_supports_direct_and_file_backed_password(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            direct = database_config.database_values(self.env)
        self.assertEqual(direct[2], INLINE_VALUES['DB_PASSWORD'])

        password_file = self.root / 'db-password'
        password_file.write_text(INLINE_VALUES['DB_PASSWORD'], encoding='utf-8')
        migrated = self.root / 'migrated.env'
        migrated.write_text(
            self.env.read_text(encoding='utf-8').replace(
                f"DB_PASSWORD={INLINE_VALUES['DB_PASSWORD']}",
                f'DB_PASSWORD_FILE={password_file}',
            ),
            encoding='utf-8',
        )
        with mock.patch.dict(os.environ, {}, clear=True):
            file_backed = database_config.database_values(migrated)
        self.assertEqual(file_backed[2], INLINE_VALUES['DB_PASSWORD'])

    def test_database_reader_errors_do_not_disclose_value_or_path(self):
        with mock.patch.dict(
            os.environ,
            {'DB_PASSWORD_FILE': str(self.root / 'other-password')},
            clear=True,
        ):
            with self.assertRaises(ValueError) as caught:
                database_config.database_values(self.env)
        message = str(caught.exception)
        self.assertNotIn(INLINE_VALUES['DB_PASSWORD'], message)
        self.assertNotIn(str(self.root), message)

    def test_operational_paths_enforce_the_installed_boundary(self):
        deploy_backend = (ROOT / 'scripts/deploy_backend.sh').read_text(encoding='utf-8')
        deploy_python = (ROOT / 'scripts/deploy_python_env.sh').read_text(encoding='utf-8')
        installer = (ROOT / 'scripts/install_security_monitor.sh').read_text(encoding='utf-8')
        migration = (ROOT / 'scripts/migrate_application_credentials.sh').read_text(
            encoding='utf-8',
        )
        for source in (deploy_backend, deploy_python, installer):
            self.assertIn('aichat-application-credential-check', source)
            self.assertIn('application-credentials', source)
        self.assertIn('aichat-read-database-config', deploy_backend)
        self.assertIn('aichat-read-database-config', installer)
        self.assertIn("temporary=\"$(mktemp -d /run/", migration)
        self.assertIn('Application credential migration completed with no persistent', migration)
        self.assertIn('runuser --user micu -- env HOME=/home/micu', migration)
        self.assertIn("setfacl -m 'u:micu:--x' -- \"$CREDENTIAL_PARENT\"", migration)
        self.assertIn('setfacl --restore="$temporary/credential-parent.acl"', migration)
        self.assertIn('restore_watcher', migration)
        self.assertNotIn('/home/micu/backups/nvidia_config', migration)

    def test_backup_restore_and_watcher_cover_the_new_boundary(self):
        backup = (ROOT / 'scripts/backup_db.sh').read_text(encoding='utf-8')
        restore = (ROOT / 'scripts/backup_restore_drill.sh').read_text(encoding='utf-8')
        watcher = (ROOT / 'ops/systemd/aichat-config-watch.path').read_text(
            encoding='utf-8',
        )
        self.assertIn('read_database_config.py', backup)
        self.assertIn('read_database_config.py', restore)
        for target in (
            '/etc/aichat/application-credentials',
            '/usr/local/libexec/aichat-application-credential-check',
            '/usr/local/libexec/aichat-read-database-config',
        ):
            self.assertIn(f'PathChanged={target}\n', watcher)
        self.assertEqual(watcher.count('PathChanged='), 30)


if __name__ == '__main__':
    unittest.main()
