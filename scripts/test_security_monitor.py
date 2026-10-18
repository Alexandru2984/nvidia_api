import importlib.util
import hashlib
import os
import socket
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
            ['event=auth_failed'] * 5
            + ['event=recent_auth_failed'] * 5
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
            + ['event=attachment_malware_rejected source=upload user_id=4']
            + ['event=attachment_scanner_unavailable source=image user_id=4']
            + ['event=attachment_parser_unavailable user_id=4']
            + ['event=document_parser_failure type=pdf reason=timeout']
            + ['event=provider_protocol_rejected kind=chat reason=bounds_or_shape']
            + ['event=two_factor_key_error operation=totp_login user_id=4']
            + ['event=model_status_invalid reason=schema']
            + ['event=model_probe_degraded inconclusive=2']
            + ['event=model_probe_authorization_failed count=2']
            + ['event=protected_config_changed']
            + ['event=generation_idempotency_conflict'] * 3
            + ['event=generation_request_interrupted']
            + ['event=account_export_completed user_id=4 records=6 bytes=2048']
            + ['event=account_export_bound_exceeded user_id=4']
            + ['event=proxy_client_ip_invalid']
            + ['event=account_deleted former_user_id=4 sessions_revoked=2']
            + ['event=account_deletion_scheduled user_id=4']
            + ['event=account_deletion_canceled user_id=4']
            + ['event=account_deletion_executed former_user_id=4 sessions_revoked=2']
            + ["aichat-maintenance.service: Failed with result 'exit-code'."]
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
             'attachment_malware', 'attachment_scanner_unavailable',
             'attachment_parser_unavailable', 'document_parser_failure',
             'provider_protocol_rejected', 'two_factor_key_error',
             'model_status_invalid',
             'model_probe_degraded',
             'model_probe_authorization',
             'protected_config_changed',
             'generation_idempotency_conflict', 'generation_interrupted',
             'account_export_completed', 'account_export_bound_exceeded',
             'proxy_client_ip_invalid',
             'account_deleted',
             'account_deletion_scheduled', 'account_deletion_canceled',
             'account_deletion_executed',
             'maintenance_failed',
             'registration_invite_consumed', 'registration_verified', 'error_burst'},
        )
        self.assertNotIn('user_id', issues['account_export_completed'])
        self.assertNotIn('user_id', issues['account_export_bound_exceeded'])

    def test_clamav_database_requires_recent_protected_daily_signatures(self):
        database_dir = self.root / 'clamav'
        database_dir.mkdir(mode=0o755)
        database = database_dir / 'daily.cvd'
        database.write_bytes(b'signed fixture')
        database.chmod(0o644)

        self.assertEqual(
            monitor.evaluate_clamav_database(database_dir, now=time.time()),
            {},
        )

        old = time.time() - monitor.CLAMAV_DATABASE_MAX_AGE_SECONDS - 60
        os.utime(database, (old, old))
        self.assertIn(
            'malware_database_stale',
            monitor.evaluate_clamav_database(database_dir, now=time.time()),
        )
        database.chmod(0o666)
        self.assertIn(
            'malware_database_integrity',
            monitor.evaluate_clamav_database(database_dir, now=time.time()),
        )

    def test_clamav_database_rejects_missing_or_symlinked_daily_signatures(self):
        database_dir = self.root / 'clamav'
        database_dir.mkdir(mode=0o755)
        self.assertIn(
            'malware_database_integrity',
            monitor.evaluate_clamav_database(database_dir),
        )
        (database_dir / 'daily.cld').symlink_to(self.dump)
        self.assertIn(
            'malware_database_integrity',
            monitor.evaluate_clamav_database(database_dir),
        )

    def test_clamav_socket_rejects_non_socket_path_without_connecting(self):
        not_a_socket = self.root / 'clamd.ctl'
        not_a_socket.write_bytes(b'not a socket')
        with mock.patch.object(monitor.socket, 'socket') as socket_factory:
            issues = monitor.evaluate_clamav_socket(not_a_socket)
        self.assertIn('malware_scanner_health', issues)
        socket_factory.assert_not_called()

    def test_clamav_socket_requires_exact_pong(self):
        socket_path = self.root / 'clamd.ctl'
        socket_path.touch(mode=0o660)
        socket_info = mock.Mock(st_mode=stat.S_IFSOCK | 0o660)
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.recv.return_value = b'PONG\0'
        with (
            mock.patch.object(Path, 'lstat', return_value=socket_info),
            mock.patch.object(monitor.socket, 'socket', return_value=client),
        ):
            self.assertEqual(monitor.evaluate_clamav_socket(socket_path), {})
        client.connect.assert_called_once_with(str(socket_path))
        client.sendall.assert_called_once_with(b'zPING\0')

        client.recv.return_value = b'UNKNOWN\0'
        with (
            mock.patch.object(Path, 'lstat', return_value=socket_info),
            mock.patch.object(monitor.socket, 'socket', return_value=client),
        ):
            self.assertIn(
                'malware_scanner_health',
                monitor.evaluate_clamav_socket(socket_path),
            )

    def test_backend_origin_socket_requires_private_exact_shape(self):
        runtime = self.root / 'backend-runtime'
        runtime.mkdir(mode=0o750)
        path = runtime / 'gunicorn.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(path))
            path.chmod(0o660)
            self.assertEqual(
                monitor.evaluate_backend_origin_socket(
                    path, expected_uid=os.geteuid(), expected_gid=os.getegid(),
                ),
                {},
            )
            path.chmod(0o666)
            self.assertIn(
                'backend_origin_socket',
                monitor.evaluate_backend_origin_socket(
                    path, expected_uid=os.geteuid(), expected_gid=os.getegid(),
                ),
            )
        finally:
            server.close()

    def test_forbidden_backend_tcp_alerts_only_when_reachable(self):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.connect_ex.return_value = 111
        with mock.patch.object(monitor.socket, 'socket', return_value=client):
            self.assertEqual(monitor.evaluate_forbidden_backend_tcp(), {})
        client.connect_ex.return_value = 0
        with mock.patch.object(monitor.socket, 'socket', return_value=client):
            self.assertIn(
                'backend_tcp_origin',
                monitor.evaluate_forbidden_backend_tcp(),
            )

    def test_document_parser_socket_requires_exact_private_health_response(self):
        socket_path = self.root / 'parser.sock'
        socket_path.touch(mode=0o660)
        socket_info = mock.Mock(st_mode=stat.S_IFSOCK | 0o660)
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = [monitor.PARSER_RESPONSE.pack(monitor.PARSER_MAGIC, 0, 0), b'']
        with (
            mock.patch.object(Path, 'lstat', return_value=socket_info),
            mock.patch.object(monitor.socket, 'socket', return_value=client),
        ):
            self.assertEqual(monitor.evaluate_document_parser_socket(socket_path), {})
        client.connect.assert_called_once_with(str(socket_path))
        client.sendall.assert_called_once_with(
            monitor.PARSER_REQUEST.pack(monitor.PARSER_MAGIC, 0, 0, 0),
        )

        unsafe_info = mock.Mock(st_mode=stat.S_IFSOCK | 0o666)
        with (
            mock.patch.object(Path, 'lstat', return_value=unsafe_info),
            mock.patch.object(monitor.socket, 'socket') as socket_factory,
        ):
            issues = monitor.evaluate_document_parser_socket(socket_path)
        self.assertIn('document_parser_health', issues)
        socket_factory.assert_not_called()

    def create_document_parser_installation(self):
        backend_live, _, _ = self.create_backend_release()
        chat = backend_live.resolve() / 'chat'
        service_source = chat / 'document_parser_service.py'
        worker_source = chat / 'document_worker.py'
        service_source.write_bytes(b'service fixture\n')
        worker_source.write_bytes(b'worker fixture\n')
        service_source.chmod(0o644)
        worker_source.chmod(0o644)
        installed_service = self.root / 'aichat-document-parser'
        installed_worker = self.root / 'aichat-document-worker'
        installed_service.write_bytes(service_source.read_bytes())
        installed_worker.write_bytes(worker_source.read_bytes())
        installed_service.chmod(0o755)
        installed_worker.chmod(0o755)
        return backend_live, installed_service, installed_worker

    def test_document_parser_installation_matches_active_release(self):
        backend_live, installed_service, installed_worker = (
            self.create_document_parser_installation()
        )
        self.assertEqual(
            monitor.evaluate_document_parser_installation(
                backend_live,
                installed_service,
                installed_worker,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            ),
            {},
        )

    def test_document_parser_installation_detects_tampering_and_modes(self):
        backend_live, installed_service, installed_worker = (
            self.create_document_parser_installation()
        )
        installed_worker.write_bytes(b'tampered worker\n')
        issues = monitor.evaluate_document_parser_installation(
            backend_live,
            installed_service,
            installed_worker,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertIn('document_parser_integrity', issues)

        installed_worker.write_bytes(
            (backend_live.resolve() / 'chat' / 'document_worker.py').read_bytes(),
        )
        installed_worker.chmod(0o775)
        issues = monitor.evaluate_document_parser_installation(
            backend_live,
            installed_service,
            installed_worker,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertIn('document_parser_integrity', issues)

    def test_evaluate_rejects_partial_parser_integrity_configuration(self):
        issues = monitor.evaluate(
            self.backups,
            self.restore_log,
            '',
            document_parser_service=self.root / 'missing',
        )
        self.assertIn('document_parser_integrity', issues)

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

    def test_state_rejects_unsafe_mode_or_different_owner(self):
        state_path = self.root / 'state' / 'state.json'
        monitor.save_state(state_path, {'active': [], 'last_sent': {}})

        state_path.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, 'unsafe ownership or permissions'):
            monitor.load_state(state_path)

        state_path.chmod(0o600)
        with mock.patch.object(monitor.os, 'geteuid', return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(RuntimeError, 'unsafe ownership or permissions'):
                monitor.load_state(state_path)

    def test_credentials_parser_accepts_quotes(self):
        env_file = self.root / 'monitor.env'
        env_file.write_text("BOT_TOKEN='token-value'\nCHAT_ID=12345\nIGNORED=value\n", encoding='utf-8')
        env_file.chmod(0o600)
        self.assertEqual(
            monitor.parse_monitor_credentials(env_file),
            {'BOT_TOKEN': 'token-value', 'CHAT_ID': '12345'},
        )

    def test_credentials_parser_rejects_permissive_or_symlinked_file(self):
        env_file = self.root / 'monitor.env'
        env_file.write_text('BOT_TOKEN=token\nCHAT_ID=1\n', encoding='utf-8')
        env_file.chmod(0o640)
        with self.assertRaisesRegex(RuntimeError, 'credentials are unsafe'):
            monitor.parse_monitor_credentials(env_file)
        env_file.chmod(0o600)
        link = self.root / 'monitor-link.env'
        link.symlink_to(env_file)
        with self.assertRaisesRegex(RuntimeError, 'credentials are unsafe'):
            monitor.parse_monitor_credentials(link)

    def test_credentials_parser_accepts_only_exact_systemd_acl(self):
        credential_dir = self.root / 'credentials'
        credential_dir.mkdir()
        env_file = credential_dir / 'telegram.env'
        env_file.write_text('BOT_TOKEN=token\nCHAT_ID=1\n', encoding='utf-8')
        root_systemd_info = SimpleNamespace(
            st_mode=stat.S_IFREG | 0o440,
            st_uid=0,
            st_gid=0,
            st_size=env_file.stat().st_size,
        )
        with (
            mock.patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(credential_dir)}),
            mock.patch.object(Path, 'lstat', return_value=root_systemd_info),
            mock.patch.object(monitor, '_has_exact_acl', return_value=True),
        ):
            self.assertEqual(
                monitor.parse_monitor_credentials(env_file),
                {'BOT_TOKEN': 'token', 'CHAT_ID': '1'},
            )
        with (
            mock.patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': str(credential_dir)}),
            mock.patch.object(Path, 'lstat', return_value=root_systemd_info),
            mock.patch.object(monitor, '_has_exact_acl', return_value=False),
        ):
            with self.assertRaisesRegex(RuntimeError, 'credentials are unsafe'):
                monitor.parse_monitor_credentials(env_file)

    def test_dedicated_monitor_backup_acl_geometry(self):
        self.backups.chmod(0o750)
        self.restore_log.chmod(0o640)
        with mock.patch.object(monitor, '_has_exact_acl', return_value=True):
            issues = monitor.evaluate(
                self.backups,
                self.restore_log,
                '',
                backup_expected_uid=os.getuid(),
                backup_expected_gid=os.getgid(),
                backup_monitor_uid=os.getuid() + 1,
            )
        self.assertEqual(issues, {})

        with mock.patch.object(monitor, '_has_exact_acl', return_value=False):
            issues = monitor.evaluate(
                self.backups,
                self.restore_log,
                '',
                backup_expected_uid=os.getuid(),
                backup_expected_gid=os.getgid(),
                backup_monitor_uid=os.getuid() + 1,
            )
        self.assertIn('backup_directory_permissions', issues)
        self.assertIn('restore_log_permissions', issues)

    def test_journal_reader_uses_absolute_executable(self):
        completed = mock.Mock(returncode=0, stdout='journal', stderr='')
        with mock.patch.object(monitor.subprocess, 'run', return_value=completed) as run:
            self.assertEqual(monitor.read_journal(), 'journal')
        self.assertEqual(run.call_args.args[0][0], '/usr/bin/journalctl')

    def test_systemd_unit_uses_dedicated_identity_and_credential(self):
        unit = (
            Path(__file__).resolve().parents[1]
            / 'ops/systemd/aichat-security-monitor.service'
        ).read_text(encoding='utf-8')
        self.assertIn('User=aichat-monitor\n', unit)
        self.assertIn('Group=aichat-monitor\n', unit)
        self.assertIn('LoadCredential=telegram.env:/home/micu/scripts/.env\n', unit)
        self.assertIn('--credentials=%d/telegram.env', unit)
        self.assertNotIn('User=micu\n', unit)
        self.assertNotIn('BindReadOnlyPaths=/home/micu/backups/nvidia_db /home/micu/scripts/.env', unit)

        path_unit = (
            Path(__file__).resolve().parents[1]
            / 'ops/systemd/aichat-config-watch.path'
        ).read_text(encoding='utf-8')
        self.assertIn('PathChanged=/home/micu/nvidia/backend/.env\n', path_unit)
        self.assertIn('PathChanged=/etc/nginx/sites-available/aichat.micutu.com\n', path_unit)
        self.assertIn('PathChanged=/usr/local/libexec/aichat-security-monitor\n', path_unit)

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
        requirements_lock = release / '.release-requirements.lock'
        requirements_hash = release / '.release-requirements.sha256'
        sbom = release / '.release-sbom.cdx.json'
        python.write_bytes(b'python fixture\n')
        package.write_text('VERSION = 1\n', encoding='utf-8')
        template.write_text('<types />\n', encoding='utf-8')
        commit.write_text('b' * 40 + '\n', encoding='ascii')
        requirements.write_text('package==1\n', encoding='ascii')
        requirements_lock.write_text('package==1 --hash=sha256:' + 'a' * 64 + '\n', encoding='ascii')
        requirements_hash.write_text('fixture\n', encoding='ascii')
        sbom.write_text('{}\n', encoding='ascii')
        python.chmod(0o755)
        for path in (
            package, template, commit, requirements, requirements_lock,
            requirements_hash, sbom,
        ):
            path.chmod(0o644)
        manifest = release / monitor.RELEASE_MANIFEST
        files = (
            commit, requirements, requirements_lock, requirements_hash, sbom,
            python, package, template,
        )
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

    def test_python_environment_manifest_requires_sbom(self):
        live, release_root, _ = self.create_python_environment_release()
        sbom = live.resolve() / '.release-sbom.cdx.json'
        sbom.unlink()
        manifest = live.resolve() / monitor.RELEASE_MANIFEST
        manifest.write_text(
            ''.join(
                f'{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{path.relative_to(live.resolve())}\n'
                for path in live.resolve().rglob('*')
                if path.is_file() and path.name != monitor.RELEASE_MANIFEST
            ),
            encoding='ascii',
        )
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
