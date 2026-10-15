#!/usr/bin/python3
import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('configure_two_factor_keys.py')
SPEC = importlib.util.spec_from_file_location('configure_two_factor_keys', SCRIPT)
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


class ConfigureTwoFactorKeysTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.env = self.root / '.env'
        self.env.write_text('DJANGO_SECRET_KEY=preserve-me\nDB_PASSWORD=also-preserve\n')
        self.env.chmod(0o640)

    def tearDown(self):
        self.temporary.cleanup()

    def values(self):
        return dict(
            line.split('=', 1)
            for line in self.env.read_text().splitlines()
            if line and not line.startswith('#') and '=' in line
        )

    def test_bootstrap_preserves_existing_secrets_and_permissions(self):
        config.configure(self.env, 'prod-2026-10', rotate=False)
        values = self.values()
        self.assertEqual(values['DJANGO_SECRET_KEY'], 'preserve-me')
        self.assertEqual(values['DB_PASSWORD'], 'also-preserve')
        self.assertEqual(values['TWO_FACTOR_ACTIVE_KEY_ID'], 'prod-2026-10')
        self.assertEqual(values['TWO_FACTOR_LEGACY_SECRET_KEY_ENABLED'], 'false')
        self.assertEqual(set(json.loads(values['TWO_FACTOR_KEYS'])), {'prod-2026-10'})
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o640)
        self.assertEqual(self.env.stat().st_uid, os.geteuid())
        self.assertEqual(self.env.stat().st_gid, os.getegid())

    def test_rotation_retains_old_key_and_changes_active_identifier(self):
        config.configure(self.env, 'first', rotate=False)
        first = json.loads(self.values()['TWO_FACTOR_KEYS'])['first']
        config.configure(self.env, 'second', rotate=True)
        values = self.values()
        keyring = json.loads(values['TWO_FACTOR_KEYS'])
        self.assertEqual(keyring['first'], first)
        self.assertIn('second', keyring)
        self.assertNotEqual(keyring['first'], keyring['second'])
        self.assertEqual(values['TWO_FACTOR_ACTIVE_KEY_ID'], 'second')

    def test_bootstrap_refuses_existing_managed_settings(self):
        config.configure(self.env, 'first', rotate=False)
        with self.assertRaises(config.ConfigurationError):
            config.configure(self.env, 'second', rotate=False)

    def test_refuses_unsafe_permissions_and_symlinks(self):
        self.env.chmod(0o644)
        with self.assertRaises(config.ConfigurationError):
            config.configure(self.env, 'first', rotate=False)
        self.env.unlink()
        target = self.root / 'target'
        target.write_text('DJANGO_SECRET_KEY=x\n')
        target.chmod(0o600)
        self.env.symlink_to(target)
        with self.assertRaises(config.ConfigurationError):
            config.configure(self.env, 'first', rotate=False)


if __name__ == '__main__':
    unittest.main()
