import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'security_monitor', Path(__file__).with_name('security_monitor.py'),
)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class SecurityMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.backups = self.root / 'backups'
        self.backups.mkdir(mode=0o700)
        self.dump = self.backups / 'nvidia_db_20261005_172709_123.sql.gz'
        self.dump.write_bytes(b'test fixture')
        self.dump.chmod(0o600)
        self.restore_log = self.backups / 'restore-drill.log'
        self.restore_log.write_text('2026-10-05 restore drill ok: fixture\n', encoding='utf-8')
        self.restore_log.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def test_clean_state_has_no_issues(self):
        self.assertEqual(monitor.evaluate(self.backups, self.restore_log, ''), {})

    def test_detects_auth_rate_admin_budget_and_error_signals(self):
        journal = '\n'.join(
            ['event=auth_failed'] * 10
            + ['event=rate_limit'] * 20
            + ['event=admin_access_denied'] * 10
            + ['event=admin_access user_id=1', 'event=two_factor_disabled',
               'event=ai_budget_blocked scope=global',
               'event=ai_token_reservation_exceeded']
            + ['event=ai_usage_unmetered'] * 3
            + ['Internal Server Error:'] * 3
        )
        issues = monitor.evaluate(self.backups, self.restore_log, journal)
        self.assertEqual(
            set(issues),
            {'auth_burst', 'rate_limit_burst', 'admin_probe_burst', 'admin_access',
             'two_factor_disabled', 'global_budget', 'unmetered_ai_usage',
             'token_reservation_overrun', 'error_burst'},
        )

    def test_detects_stale_or_permissive_backup(self):
        old = time.time() - monitor.BACKUP_MAX_AGE_SECONDS - 60
        os.utime(self.dump, (old, old))
        self.dump.chmod(0o640)
        issues = monitor.evaluate(self.backups, self.restore_log, '')
        self.assertIn('backup_stale', issues)
        self.assertIn('backup_permissions', issues)

    def test_last_restore_line_must_be_success(self):
        with self.restore_log.open('a', encoding='utf-8') as handle:
            handle.write('ERROR: restore failed\n')
        issues = monitor.evaluate(self.backups, self.restore_log, '')
        self.assertIn('restore_failed', issues)

    def test_state_round_trip_is_private(self):
        state_path = self.root / 'state' / 'state.json'
        expected = {'active': ['auth_burst'], 'last_sent': {'auth_burst': 1}}
        monitor.save_state(state_path, expected)
        self.assertEqual(monitor.load_state(state_path), expected)
        self.assertEqual(state_path.stat().st_mode & 0o777, 0o600)

    def test_credentials_parser_accepts_quotes(self):
        env_file = self.root / 'monitor.env'
        env_file.write_text("BOT_TOKEN='token-value'\nCHAT_ID=12345\nIGNORED=value\n", encoding='utf-8')
        self.assertEqual(
            monitor.parse_monitor_credentials(env_file),
            {'BOT_TOKEN': 'token-value', 'CHAT_ID': '12345'},
        )


if __name__ == '__main__':
    unittest.main()
