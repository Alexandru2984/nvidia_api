#!/usr/bin/env python3
"""Structural regressions for the signed, credential-minimal model probe."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
SERVICE = ROOT / 'ops/systemd/aichat-model-probe.service'
SYSUSERS = ROOT / 'ops/sysusers.d/aichat-model-probe.conf'
INSTALLER = ROOT / 'scripts/install_model_probe_identity.sh'
DEPLOYER = ROOT / 'scripts/deploy_backend.sh'
PROBE_SETTINGS = ROOT / 'backend/nvidia_chat/probe_settings.py'
CHECK_SETTINGS = ROOT / 'backend/nvidia_chat/model_status_check_settings.py'
MAIN_SETTINGS = ROOT / 'backend/nvidia_chat/settings.py'


class ModelProbeIsolationTests(unittest.TestCase):
    def test_service_has_dedicated_identity_and_only_scoped_credentials(self):
        unit = SERVICE.read_text(encoding='utf-8')
        self.assertIn('User=aichat-model-probe\n', unit)
        self.assertIn('Group=aichat\n', unit)
        self.assertNotIn('User=aichat\n', unit)
        self.assertNotIn('/home/micu/nvidia/backend/.env', unit)
        self.assertIn(
            'LoadCredential=nvidia-api-key:/etc/aichat/model-probe-api-key\n',
            unit,
        )
        self.assertIn(
            'LoadCredential=model-status-private-key:/etc/aichat/model-status-private.pem\n',
            unit,
        )
        self.assertIn('StateDirectory=aichat-model-probe\n', unit)
        self.assertIn('StateDirectoryMode=0750\n', unit)
        self.assertIn('UMask=0027\n', unit)
        self.assertIn('ProtectSystem=strict\n', unit)
        self.assertIn('ProtectHome=tmpfs\n', unit)
        self.assertIn('NoNewPrivileges=yes\n', unit)
        self.assertIn('CapabilityBoundingSet=\n', unit)
        self.assertIn('SocketBindDeny=any\n', unit)
        self.assertIn(
            'ExecStart=/opt/aichat-python-current/bin/python '
            '/opt/aichat-backend-current/probe_models.py\n',
            unit,
        )

    def test_probe_settings_do_not_import_application_settings_or_dotenv(self):
        settings = PROBE_SETTINGS.read_text(encoding='utf-8')
        self.assertNotIn('from .settings import', settings)
        self.assertNotIn('load_dotenv', settings)
        self.assertNotIn('DB_', settings)
        self.assertNotIn('SMTP_', settings)
        self.assertNotIn('TWO_FACTOR_', settings)
        self.assertNotIn('ADMIN_AUDIT_', settings)
        self.assertIn("INSTALLED_APPS = []\n", settings)
        self.assertIn("NVIDIA_API_KEY = _credential('nvidia-api-key')\n", settings)
        self.assertIn('MODEL_STATUS_SIGNATURE_REQUIRED = True\n', settings)
        self.assertIn('MODEL_STATUS_SECURE_PERMISSIONS_REQUIRED = True\n', settings)

    def test_production_backend_reads_probe_owned_signed_state(self):
        settings = MAIN_SETTINGS.read_text(encoding='utf-8')
        self.assertIn("Path('/var/lib/aichat-model-probe/model_status.json')", settings)
        self.assertIn("'MODEL_STATUS_SIGNATURE_REQUIRED', not DEBUG", settings)
        self.assertIn("'MODEL_STATUS_EXPECTED_OWNER', 'aichat-model-probe'", settings)
        self.assertIn("'MODEL_STATUS_EXPECTED_GROUP', 'aichat'", settings)

    def test_independent_checker_settings_are_credential_free(self):
        settings = CHECK_SETTINGS.read_text(encoding='utf-8')
        self.assertNotIn('NVIDIA_API_KEY', settings)
        self.assertNotIn('CREDENTIALS_DIRECTORY', settings)
        self.assertNotIn('load_dotenv', settings)
        self.assertIn('MODEL_STATUS_SIGNATURE_REQUIRED = True\n', settings)
        self.assertIn('MODEL_STATUS_REQUIRED = True\n', settings)

    def test_installer_extracts_only_provider_key_and_preserves_keypair(self):
        installer = INSTALLER.read_text(encoding='utf-8')
        self.assertIn("dotenv_values(source).get('NVIDIA_API_KEY')", installer)
        self.assertNotIn("dotenv_values(source).get('DB_", installer)
        self.assertIn('openssl genpkey -algorithm ED25519', installer)
        self.assertIn('public/private keys do not match', installer)
        self.assertIn("[[ \"${1:-}\" == '--rotate-signing-key' ]]", installer)
        self.assertIn("API_CREDENTIAL=\"$CONFIG_DIR/model-probe-api-key\"", installer)
        self.assertIn("PRIVATE_KEY=\"$CONFIG_DIR/model-status-private.pem\"", installer)
        self.assertIn("PUBLIC_KEY=\"$CONFIG_DIR/model-status-public.pem\"", installer)
        self.assertIn('tracked repository changes must be committed', installer)

    def test_backend_deploy_fails_closed_on_missing_probe_boundary(self):
        deployer = DEPLOYER.read_text(encoding='utf-8')
        self.assertIn('validate_model_probe_boundary() {', deployer)
        self.assertIn('validate_model_probe_boundary\n', deployer)
        self.assertIn("'--check-model-probe-boundary'", deployer)
        self.assertIn("MODEL_PROBE_USER='aichat-model-probe'", deployer)
        self.assertIn('openssl pkey -in "$MODEL_PROBE_PRIVATE_KEY" -pubout', deployer)
        self.assertIn("runuser --user aichat -- sh -c '", deployer)
        self.assertIn("== '640:aichat-model-probe:aichat'", deployer)

    def test_sysusers_identity_is_non_login(self):
        line = SYSUSERS.read_text(encoding='utf-8').strip()
        self.assertEqual(
            line,
            'u aichat-model-probe - "AI Chat Hub NVIDIA model probe" '
            '/var/lib/aichat-model-probe /usr/sbin/nologin',
        )


if __name__ == '__main__':
    unittest.main()
