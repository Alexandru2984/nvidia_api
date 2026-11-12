#!/usr/bin/env python3
"""Regression and deployment-contract tests for atomic incident controls."""

from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/incident_controls.py"
COMMAND = ROOT / "scripts/apply_incident_controls.sh"
INSTALLER = ROOT / "scripts/install_security_monitor.sh"
DEPLOY = ROOT / "scripts/deploy_backend.sh"
WATCHER = ROOT / "ops/systemd/aichat-config-watch.path"

SPEC = importlib.util.spec_from_file_location("incident_controls", HELPER)
assert SPEC and SPEC.loader
incident_controls = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = incident_controls
SPEC.loader.exec_module(incident_controls)


class IncidentControlHelperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = self.root / ".env"

    def run_helper(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [str(HELPER), "--env-file", str(self.env), *arguments],
            check=False,
            capture_output=True,
        )

    def test_stage_preserves_unrelated_lines_and_canonicalizes_controls(self):
        original = (
            "# production runtime\n"
            "DJANGO_SECRET_KEY_FILE=/etc/aichat/application-credentials/django-secret-key\n"
            "export AI_GENERATION_ENABLED='true'\n"
            "REGISTRATION_MODE=invite\n"
            "NVIDIA_API_KEY_FILE=/etc/aichat/application-credentials/nvidia-api-key\n"
        )
        self.env.write_text(original, encoding="utf-8")
        output = self.root / "staged"

        completed = self.run_helper(
            "--stage-output",
            str(output),
            "--generation",
            "disabled",
            "--registration",
            "closed",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        rendered = output.read_text(encoding="utf-8")
        self.assertIn("# production runtime\n", rendered)
        self.assertIn("DJANGO_SECRET_KEY_FILE=/etc/aichat/", rendered)
        self.assertIn("NVIDIA_API_KEY_FILE=/etc/aichat/", rendered)
        self.assertIn("AI_GENERATION_ENABLED=false\n", rendered)
        self.assertIn("REGISTRATION_MODE=closed\n", rendered)
        self.assertNotIn("export AI_GENERATION_ENABLED", rendered)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_missing_controls_are_appended_with_safe_defaults_replaced(self):
        self.env.write_text("DB_NAME=nvidia\n", encoding="utf-8")
        output = self.root / "staged"
        completed = self.run_helper(
            "--stage-output",
            str(output),
            "--generation",
            "disabled",
            "--registration",
            "invite",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            output.read_text(encoding="utf-8"),
            "DB_NAME=nvidia\nAI_GENERATION_ENABLED=false\nREGISTRATION_MODE=invite\n",
        )

    def test_show0_emits_exact_machine_readable_controls(self):
        self.env.write_text(
            'AI_GENERATION_ENABLED="false"\nREGISTRATION_MODE=invite\n',
            encoding="utf-8",
        )
        completed = self.run_helper("--show0")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b"disabled\0invite\0")

    def test_duplicate_and_invalid_values_are_rejected(self):
        invalid_documents = (
            "AI_GENERATION_ENABLED=true\nAI_GENERATION_ENABLED=false\n",
            "AI_GENERATION_ENABLED=maybe\nREGISTRATION_MODE=open\n",
            "AI_GENERATION_ENABLED=true\nREGISTRATION_MODE=public\n",
            "AI_GENERATION_ENABLED=true # ignored\nREGISTRATION_MODE=open\n",
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                self.env.write_text(document, encoding="utf-8")
                completed = self.run_helper("--show0")
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(completed.stdout, b"")

    def test_unsafe_input_types_sizes_and_bytes_are_rejected(self):
        real = self.root / "real"
        real.write_text("AI_GENERATION_ENABLED=true\n", encoding="utf-8")
        self.env.symlink_to(real)
        self.assertNotEqual(self.run_helper("--show0").returncode, 0)
        self.env.unlink()

        os.mkfifo(self.env)
        self.assertNotEqual(self.run_helper("--show0").returncode, 0)
        self.env.unlink()

        self.env.write_bytes(b"X=" + b"a" * (incident_controls.MAX_ENV_BYTES + 1))
        self.assertNotEqual(self.run_helper("--show0").returncode, 0)
        self.env.write_bytes(b"AI_GENERATION_ENABLED=true\nBAD=\xff\n")
        self.assertNotEqual(self.run_helper("--show0").returncode, 0)
        self.env.write_bytes(b"AI_GENERATION_ENABLED=true\nBAD=\x00\n")
        self.assertNotEqual(self.run_helper("--show0").returncode, 0)

    def test_stage_output_is_exclusive_and_refuses_symlinks(self):
        self.env.write_text("AI_GENERATION_ENABLED=true\n", encoding="utf-8")
        protected = self.root / "protected"
        protected.write_text("unchanged", encoding="utf-8")
        for output in (self.root / "existing", self.root / "link"):
            if output.name == "existing":
                output.write_text("unchanged", encoding="utf-8")
            else:
                output.symlink_to(protected)
            completed = self.run_helper(
                "--stage-output",
                str(output),
                "--generation",
                "disabled",
                "--registration",
                "closed",
            )
            self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(protected.read_text(encoding="utf-8"), "unchanged")

    def test_errors_do_not_disclose_environment_content_or_path(self):
        secret = "nvapi-sensitive-value-that-must-not-appear"
        self.env.write_text(
            f"NVIDIA_API_KEY={secret}\nAI_GENERATION_ENABLED=invalid\n",
            encoding="utf-8",
        )
        completed = self.run_helper("--show0")
        error = completed.stderr.decode("utf-8")
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotIn(secret, error)
        self.assertNotIn(str(self.root), error)


class IncidentControlDeploymentContractTests(unittest.TestCase):
    def test_command_has_atomic_rollback_and_production_guards(self):
        command = COMMAND.read_text(encoding="utf-8")
        for required in (
            "CONTROL_TOOL='/usr/local/libexec/aichat-incident-control-render'",
            "RELEASE_LOCK='/run/aichat-release-operation.lock'",
            "CONTROL_LOCK='/run/aichat-incident-controls.lock'",
            "mktemp -d /run/aichat-incident-controls.XXXXXX",
            'restore_snapshot() {',
            'trap \'rollback "$?"\' ERR EXIT',
            'systemctl restart "$SERVICE"',
            'wait_for_health',
            'systemctl stop "$WATCHER"',
            'restore_watcher',
            '"https://$DOMAIN/media/incident-control-probe"',
            '"https://$DOMAIN/api/conversations/"',
            '--admin-user micu',
            'GenerationRequest.objects.filter(state__in=GenerationRequest.ACTIVE_STATES)',
            'event=incident_controls_exercise_restored',
        ):
            self.assertIn(required, command)
        self.assertIn('cp -a -- "$ENV_FILE" "$temporary/env.before"', command)
        self.assertNotIn('/home/micu/backups', command)
        exercise_guard = command.index('if [[ "$operation" == exercise ]]; then', 5000)
        active_guard = command.index('active_requests=', exercise_guard)
        apply_trap = command.index("trap 'rollback", active_guard)
        self.assertLess(exercise_guard, active_guard)
        self.assertLess(active_guard, apply_trap)

    def test_installer_and_deploy_enforce_root_owned_byte_exact_tools(self):
        installer = INSTALLER.read_text(encoding="utf-8")
        deploy = DEPLOY.read_text(encoding="utf-8")
        for source, target in (
            ("incident_controls.py", "/usr/local/libexec/aichat-incident-control-render"),
            ("apply_incident_controls.sh", "/usr/local/sbin/aichat-incident-controls"),
        ):
            self.assertIn(source, installer)
            self.assertIn(target, installer)
            self.assertIn(source, deploy)
            self.assertIn(target, deploy)
        self.assertIn('install -o root -g root -m 0755 --', installer)
        self.assertIn('cmp --silent -- "$SOURCE_INCIDENT_RENDERER"', installer)
        self.assertIn('cmp --silent -- "$SOURCE_INCIDENT_COMMAND"', installer)
        self.assertIn('incident_renderer) target=', installer)
        self.assertIn('incident_command) target=', installer)
        self.assertIn('restore_target incident_renderer', installer)
        self.assertIn('restore_target incident_command', installer)
        self.assertIn("== '755:root:root'", deploy)

    def test_watcher_covers_both_installed_tools(self):
        watcher = WATCHER.read_text(encoding="utf-8")
        self.assertIn(
            "PathChanged=/usr/local/libexec/aichat-incident-control-render\n",
            watcher,
        )
        self.assertIn(
            "PathChanged=/usr/local/sbin/aichat-incident-controls\n",
            watcher,
        )
        self.assertEqual(watcher.count("PathChanged="), 30)


if __name__ == "__main__":
    unittest.main()
