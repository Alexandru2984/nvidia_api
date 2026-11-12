import grp
import importlib.util
import os
import pwd
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / 'scripts/check_runtime_secret_hygiene.py'

SPEC = importlib.util.spec_from_file_location('runtime_secret_hygiene', CHECKER)
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


class RuntimeSecretHygieneTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.runtime = Path(self.temp.name) / 'backend'
        self.runtime.mkdir(mode=0o750)
        self.dotenv = self.runtime / '.env'
        self.dotenv.write_text('DJANGO_SECRET_KEY=test-fixture\n', encoding='utf-8')
        self.dotenv.chmod(0o640)
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self):
        self.temp.cleanup()

    def evaluate(self):
        return hygiene.validate_runtime_secret_hygiene(
            self.runtime,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def test_accepts_one_bounded_dotenv_and_public_example(self):
        (self.runtime / '.env.example').write_text('PUBLIC=fixture\n', encoding='utf-8')
        self.assertEqual(self.evaluate(), [])

    def test_rejects_dotenv_copies_without_disclosing_their_names(self):
        secret_name = 'customer-secret.env.backup'
        (self.runtime / secret_name).write_text('SECRET=fixture\n', encoding='utf-8')
        failures = self.evaluate()
        self.assertEqual(failures, ['runtime directory contains a forbidden dotenv copy'])
        self.assertNotIn(secret_name, '\n'.join(failures))

    def test_rejects_symlinked_or_broad_active_dotenv(self):
        self.dotenv.unlink()
        self.dotenv.symlink_to(self.runtime / '.env.example')
        self.assertIn('active dotenv ownership, mode or shape is unsafe', self.evaluate())
        self.dotenv.unlink()
        self.dotenv.write_text('SECRET=fixture\n', encoding='utf-8')
        self.dotenv.chmod(0o644)
        self.assertIn('active dotenv ownership, mode or shape is unsafe', self.evaluate())

    def test_cli_is_content_free_and_enforces_expected_identity(self):
        owner = pwd.getpwuid(self.uid).pw_name
        group = grp.getgrgid(self.gid).gr_name
        result = subprocess.run(
            [
                str(CHECKER), '--runtime-dir', str(self.runtime),
                '--owner', owner, '--group', group,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(result.stdout, 'Runtime secret hygiene is valid.\n')

    def test_deploy_and_monitor_install_use_root_owned_checker(self):
        deployer = (ROOT / 'scripts/deploy_backend.sh').read_text(encoding='utf-8')
        installer = (ROOT / 'scripts/install_security_monitor.sh').read_text(encoding='utf-8')
        target = '/usr/local/libexec/aichat-runtime-secret-check'
        self.assertIn(f"RUNTIME_SECRET_CHECK='{target}'", deployer)
        self.assertIn('cmp --silent -- "$RUNTIME_SECRET_CHECK_SOURCE"', deployer)
        self.assertIn('"$RUNTIME_SECRET_CHECK" --runtime-dir "$RUNTIME_DIR"', deployer)
        self.assertIn(f"TARGET_SECRET_CHECK='{target}'", installer)
        self.assertIn('"$SOURCE_SECRET_CHECK" --runtime-dir "$RUNTIME_DIR"', installer)
        self.assertIn('"$TARGET_SECRET_CHECK" --runtime-dir "$RUNTIME_DIR"', installer)


if __name__ == '__main__':
    unittest.main()
