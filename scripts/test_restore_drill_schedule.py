#!/usr/bin/env python3
"""Structural regressions for the scheduled isolated database restore drill."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
SERVICE = ROOT / 'ops/systemd/aichat-restore-drill.service'
TIMER = ROOT / 'ops/systemd/aichat-restore-drill.timer'
WATCH = ROOT / 'ops/systemd/aichat-config-watch.path'
INSTALLER = ROOT / 'scripts/install_security_monitor.sh'
DRILL = ROOT / 'scripts/backup_restore_drill.sh'


class RestoreDrillScheduleTests(unittest.TestCase):
    def test_service_uses_immutable_code_and_release_paths(self):
        unit = SERVICE.read_text(encoding='utf-8')
        self.assertIn('User=micu\n', unit)
        self.assertIn('ExecStart=/usr/local/libexec/aichat-restore-drill\n', unit)
        self.assertIn('Environment=AICHAT_APP_DIR=/opt/aichat-backend-current\n', unit)
        self.assertIn('Environment=AICHAT_PYTHON=/opt/aichat-python-current/bin/python\n', unit)
        self.assertIn(
            'StandardOutput=append:/home/micu/backups/nvidia_db/restore-drill.log\n',
            unit,
        )
        self.assertIn('ProtectSystem=strict\n', unit)
        self.assertIn('ProtectHome=tmpfs\n', unit)
        self.assertIn('PrivateDevices=yes\n', unit)
        self.assertIn('IPAddressDeny=any\n', unit)
        self.assertIn('IPAddressAllow=localhost\n', unit)
        self.assertIn('TimeoutStartSec=20m\n', unit)
        # The fixed script invokes the owner's existing NOPASSWD sudo rule only
        # to create/drop a local scratch database. NoNewPrivileges would make
        # that explicit transition fail and silently destroy restore coverage.
        self.assertNotIn('NoNewPrivileges=yes', unit)

    def test_timer_is_persistent_and_runs_inside_the_eight_day_slo(self):
        timer = TIMER.read_text(encoding='utf-8')
        self.assertIn('OnCalendar=Sun *-*-* 05:15:00\n', timer)
        self.assertIn('Persistent=true\n', timer)
        self.assertIn('RandomizedDelaySec=10m\n', timer)
        self.assertIn('AccuracySec=1m\n', timer)
        self.assertIn('Unit=aichat-restore-drill.service\n', timer)

    def test_installer_owns_enables_and_executes_the_drill(self):
        installer = INSTALLER.read_text(encoding='utf-8')
        for required in (
            "TARGET_RESTORE_DRILL='/usr/local/libexec/aichat-restore-drill'",
            "TARGET_RESTORE_SERVICE='/etc/systemd/system/aichat-restore-drill.service'",
            "TARGET_RESTORE_TIMER='/etc/systemd/system/aichat-restore-drill.timer'",
            'install -o root -g root -m 0755 -- "$SOURCE_RESTORE_DRILL"',
            'systemctl enable --now aichat-restore-drill.timer',
            'systemctl start aichat-restore-drill.service',
            'systemctl reset-failed aichat-restore-drill.service',
            "LEGACY_RESTORE_CRON='15 5 * * 0 umask 077; /home/micu/nvidia/scripts/backup_restore_drill.sh",
            'remove_legacy_restore_cron',
            'restore_legacy_restore_cron',
            'crontab -u "$CRONTAB_USER"',
        ):
            self.assertIn(required, installer)

    def test_protected_change_watcher_covers_all_installed_artifacts(self):
        path_unit = WATCH.read_text(encoding='utf-8')
        for target in (
            '/etc/systemd/system/aichat-restore-drill.service',
            '/etc/systemd/system/aichat-restore-drill.timer',
            '/usr/local/libexec/aichat-restore-drill',
        ):
            self.assertIn(f'PathChanged={target}\n', path_unit)
        self.assertEqual(path_unit.count('PathChanged='), 15)

    def test_drill_accepts_only_explicit_production_path_overrides(self):
        drill = DRILL.read_text(encoding='utf-8')
        self.assertIn('if [[ -n "${AICHAT_RUNTIME_DIR:-}" ]]; then', drill)
        self.assertIn('RUNTIME_DIR="$AICHAT_RUNTIME_DIR"', drill)
        self.assertIn('APP_DIR="${AICHAT_APP_DIR:-$RUNTIME_DIR}"', drill)
        self.assertIn('PYTHON="${AICHAT_PYTHON:-$RUNTIME_DIR/venv/bin/python}"', drill)
        self.assertIn('DB_NAME="$SCRATCH_DB" "$PYTHON" "$APP_DIR/manage.py"', drill)
        self.assertIn('--check --noinput --skip-checks', drill)


if __name__ == '__main__':
    unittest.main()
