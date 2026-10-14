import importlib.util
import hashlib
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
            + ['event=admin_access user_id=1', 'event=admin_change action=change',
               'event=admin_audit_integrity_failed', 'event=two_factor_disabled',
               'event=ai_budget_blocked scope=global',
               'event=ai_token_reservation_exceeded',
               'event=chat_object_quota_blocked code=messages_limit',
               'event=session_registry_mismatch user_id=4',
               *(['event=session_limit_enforced user_id=4 revoked=1'] * 3),
               'event=registration_invite_consumed',
               'event=registration_verified']
            + ['event=ai_usage_unmetered'] * 3
            + ['event=registration_invite_rejected'] * 5
            + ['event=attachment_capability_rejected'] * 5
            + ['event=model_status_invalid reason=schema']
            + ['event=model_probe_degraded inconclusive=2']
            + ['event=model_probe_authorization_failed count=2']
            + ['Internal Server Error:'] * 3
        )
        issues = monitor.evaluate(self.backups, self.restore_log, journal)
        self.assertEqual(
            set(issues),
            {'auth_burst', 'rate_limit_burst', 'admin_probe_burst', 'admin_access',
             'admin_change', 'admin_audit_integrity',
             'two_factor_disabled', 'global_budget', 'unmetered_ai_usage',
             'token_reservation_overrun', 'chat_object_quota',
             'session_registry_mismatch', 'session_limit_burst', 'invite_rejection_burst',
             'attachment_capability_burst',
             'model_status_invalid',
             'model_probe_degraded',
             'model_probe_authorization',
             'registration_invite_consumed', 'registration_verified', 'error_burst'},
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

    def create_frontend_release(self):
        release_root = self.root / 'releases'
        release = release_root / 'release-20261007T010203_123456789'
        assets = release / 'assets'
        assets.mkdir(parents=True, mode=0o755)
        release_root.chmod(0o755)
        release.chmod(0o755)
        index = release / 'index.html'
        script = assets / 'index-test.js'
        index.write_text('<!doctype html>\n', encoding='utf-8')
        script.write_text('export default true\n', encoding='utf-8')
        index.chmod(0o644)
        script.chmod(0o644)
        manifest = release / monitor.FRONTEND_MANIFEST
        manifest.write_text(
            ''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(release)}\n'
                for path in (script, index)
            ),
            encoding='ascii',
        )
        manifest.chmod(0o644)
        live = self.root / 'live'
        live.symlink_to(release)
        return live, release_root, index

    def frontend_issues(self, live, release_root):
        return monitor.evaluate_frontend_release(
            live,
            release_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    def test_frontend_release_manifest_accepts_unchanged_root_owned_shape(self):
        live, release_root, _ = self.create_frontend_release()
        self.assertEqual(self.frontend_issues(live, release_root), {})

    def test_frontend_release_manifest_detects_content_tampering(self):
        live, release_root, index = self.create_frontend_release()
        index.write_text('tampered\n', encoding='utf-8')
        self.assertIn('frontend_integrity', self.frontend_issues(live, release_root))

    def test_frontend_release_manifest_detects_unsafe_permissions(self):
        live, release_root, index = self.create_frontend_release()
        index.chmod(0o664)
        self.assertIn('frontend_integrity', self.frontend_issues(live, release_root))

    def test_frontend_release_manifest_rejects_symlinked_content(self):
        live, release_root, _ = self.create_frontend_release()
        unsafe = live.resolve() / 'assets' / 'unsafe.js'
        unsafe.symlink_to('/etc/passwd')
        self.assertIn('frontend_integrity', self.frontend_issues(live, release_root))

    def test_release_retention_detects_excess_directories(self):
        live, release_root, _ = self.create_frontend_release()
        for sequence in range(3):
            (release_root / f'release-20261007T02020{sequence}_{sequence:09d}').mkdir()
        issues = monitor.evaluate_release_retention(
            live,
            release_root,
            issue_key='frontend_release_retention',
        )
        self.assertIn('frontend_release_retention', issues)

    def test_release_retention_accepts_active_and_two_rollbacks(self):
        live, release_root, _ = self.create_frontend_release()
        for sequence in range(2):
            (release_root / f'release-20261007T02020{sequence}_{sequence:09d}').mkdir()
        self.assertEqual(
            monitor.evaluate_release_retention(
                live,
                release_root,
                issue_key='frontend_release_retention',
            ),
            {},
        )

    def test_release_retention_rejects_unrecognized_entry(self):
        live, release_root, _ = self.create_frontend_release()
        (release_root / '.staging-untrusted').mkdir()
        issues = monitor.evaluate_release_retention(
            live,
            release_root,
            issue_key='frontend_release_retention',
        )
        self.assertIn('frontend_release_retention', issues)

    def create_backend_release(self):
        release_root = self.root / 'backend-releases'
        release = release_root / 'release-20261013T010203_123456789'
        package = release / 'chat'
        package.mkdir(parents=True, mode=0o755)
        release_root.chmod(0o755)
        release.chmod(0o755)
        manage = release / 'manage.py'
        module = package / 'models.py'
        commit = release / '.release-commit'
        manage.write_text('raise SystemExit(0)\n', encoding='utf-8')
        module.write_text('DEPLOYED = True\n', encoding='utf-8')
        commit.write_text('a' * 40 + '\n', encoding='ascii')
        for path in (manage, module, commit):
            path.chmod(0o644)
        manifest = release / monitor.RELEASE_MANIFEST
        manifest.write_text(
            ''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(release)}\n'
                for path in (commit, module, manage)
            ),
            encoding='ascii',
        )
        manifest.chmod(0o644)
        live = self.root / 'backend-current'
        live.symlink_to(release)
        return live, release_root, manage

    def backend_issues(self, live, release_root):
        return monitor.evaluate_backend_release(
            live,
            release_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    def test_backend_release_manifest_accepts_unchanged_root_owned_shape(self):
        live, release_root, _ = self.create_backend_release()
        self.assertEqual(self.backend_issues(live, release_root), {})

    def test_backend_release_manifest_detects_content_tampering(self):
        live, release_root, manage = self.create_backend_release()
        manage.write_text('tampered = True\n', encoding='utf-8')
        self.assertIn('backend_integrity', self.backend_issues(live, release_root))

    def test_evaluate_rejects_partial_backend_monitor_configuration(self):
        issues = monitor.evaluate(
            self.backups,
            self.restore_log,
            '',
            backend_live=self.root / 'missing',
        )
        self.assertIn('backend_integrity', issues)

    def create_python_environment_release(self):
        release_root = self.root / 'python-envs'
        release = release_root / 'release-20261013T020304_123456789'
        bin_dir = release / 'bin'
        template_dir = release / 'lib' / 'package' / 'templates'
        bin_dir.mkdir(parents=True, mode=0o755)
        template_dir.mkdir(parents=True, mode=0o755)
        release_root.chmod(0o755)
        release.chmod(0o755)
        for directory in (path for path in release.rglob('*') if path.is_dir()):
            directory.chmod(0o755)
        python = bin_dir / 'python'
        package = release / 'lib' / 'package' / '__init__.py'
        template = template_dir / '[Content_Types].xml'
        commit = release / '.release-commit'
        requirements = release / '.release-requirements.txt'
        python.write_bytes(b'python fixture\n')
        package.write_text('VERSION = 1\n', encoding='utf-8')
        template.write_text('<types />\n', encoding='utf-8')
        commit.write_text('b' * 40 + '\n', encoding='ascii')
        requirements.write_text('package==1\n', encoding='ascii')
        python.chmod(0o755)
        for path in (package, template, commit, requirements):
            path.chmod(0o644)
        manifest = release / monitor.RELEASE_MANIFEST
        files = (commit, requirements, python, package, template)
        manifest.write_text(
            ''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(release)}\n'
                for path in files
            ),
            encoding='ascii',
        )
        manifest.chmod(0o644)
        live = self.root / 'python-current'
        live.symlink_to(release)
        return live, release_root, python

    def python_environment_issues(self, live, release_root):
        return monitor.evaluate_python_environment_release(
            live,
            release_root,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    def test_python_environment_manifest_accepts_executable_and_bracketed_path(self):
        live, release_root, _ = self.create_python_environment_release()
        self.assertEqual(self.python_environment_issues(live, release_root), {})

    def test_python_environment_manifest_rejects_non_executable_interpreter(self):
        live, release_root, python = self.create_python_environment_release()
        python.chmod(0o644)
        self.assertIn(
            'python_environment_integrity',
            self.python_environment_issues(live, release_root),
        )

    def test_evaluate_rejects_partial_python_environment_configuration(self):
        issues = monitor.evaluate(
            self.backups,
            self.restore_log,
            '',
            python_environment_live=self.root / 'missing',
        )
        self.assertIn('python_environment_integrity', issues)


if __name__ == '__main__':
    unittest.main()
