#!/usr/bin/env python3
"""Regression tests binding public privacy claims to implemented behavior."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def read(relative_path):
    return (ROOT / relative_path).read_text(encoding='utf-8')


def require_match(test_case, pattern, text, label):
    match = re.search(pattern, text, flags=re.MULTILINE | re.DOTALL)
    test_case.assertIsNotNone(match, f'cannot derive {label} from its source')
    return match


class PrivacyNoticeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.notice = read('frontend/src/PrivacyNotice.jsx')
        cls.register = read('docs/DATA_PROCESSING_REGISTER.md')
        cls.main = read('frontend/src/main.jsx')
        cls.app = read('frontend/src/App.jsx')
        cls.settings_ui = read('frontend/src/Settings.jsx')
        cls.disclosure = read('frontend/src/ProviderDisclosure.jsx')
        cls.backend_settings = read('backend/nvidia_chat/settings.py')
        cls.models = read('backend/chat/models.py')
        cls.backup = read('scripts/backup_db.sh')
        cls.ci = read('.github/workflows/ci.yml')

    def setting_default(self, name):
        direct = re.search(
            rf'^{re.escape(name)}\s*=\s*(\d+)(?:\s*\*\s*(\d+))?',
            self.backend_settings,
            flags=re.MULTILINE,
        )
        if direct:
            return int(direct.group(1)) * int(direct.group(2) or 1)
        wrapped = require_match(
            self,
            rf"{re.escape(name)}\s*=\s*_nonnegative_int_env\(\s*"
            rf"['\"]{re.escape(name)}['\"]\s*,\s*(\d+)",
            self.backend_settings,
            name,
        )
        return int(wrapped.group(1))

    def test_public_notice_and_register_versions_match(self):
        notice_version = require_match(
            self,
            r"PRIVACY_NOTICE_VERSION\s*=\s*['\"]([^'\"]+)['\"]",
            self.notice,
            'public privacy version',
        ).group(1)
        register_version = require_match(
            self,
            r'^Version: `([^`]+)`',
            self.register,
            'processing-register version',
        ).group(1)
        self.assertEqual(notice_version, register_version)
        self.assertIn(f'Version {{PRIVACY_NOTICE_VERSION}}', self.notice)

    def test_privacy_route_does_not_mount_authenticated_app(self):
        self.assertIn("normalizedPath === '/privacy' ? <PrivacyNotice /> : <App />", self.main)
        self.assertNotIn("from './api", self.notice)
        self.assertNotRegex(self.notice, r'\b(?:fetch|XMLHttpRequest)\s*\(')
        self.assertNotIn('/api/', self.notice)

    def test_every_user_entry_point_links_to_the_notice(self):
        for source, label in (
            (self.app, 'anonymous authentication'),
            (self.settings_ui, 'authenticated settings'),
            (self.disclosure, 'provider disclosure'),
        ):
            self.assertIn('href="/privacy/"', source, f'missing {label} notice link')

    def test_archived_chat_choices_match_the_model(self):
        match = require_match(
            self,
            r'DELETE_DAYS\s*=\s*\(([^)]+)\)',
            self.models,
            'archived-chat retention choices',
        )
        choices = tuple(int(value) for value in re.findall(r'\d+', match.group(1)))
        self.assertEqual(choices, (30, 90, 180, 365))
        public_claim = '30, 90, 180, or 365 inactive days'
        register_claim = '30, 90, 180 or 365 inactive'
        self.assertIn(public_claim, self.notice)
        self.assertIn(register_claim, self.register)

    def test_chat_generation_preferences_are_disclosed(self):
        for claim in ('generation preferences', 'temperature', 'maximum output tokens', 'Chat defaults'):
            self.assertIn(claim, self.notice)
        self.assertIn('Default chat model and generation preferences', self.register)
        self.assertIn('model-specific bounds', self.register)
        self.assertIn('unavailable', self.register)
        for field in ('default_temperature', 'default_max_tokens'):
            self.assertIn(field, self.models)

    def test_retention_claims_match_backend_defaults(self):
        expected = {
            'ATTACHMENT_TTL_DAYS': (30, 'Unattached uploads', '30 days'),
            'GENERATION_REQUEST_RETENTION_DAYS': (7, 'Generation job metadata', '7 days'),
            'REGISTRATION_INVITE_AUDIT_DAYS': (90, 'Invite / privileged audit', '90 days'),
            'ADMIN_AUDIT_RETENTION_DAYS': (365, 'Invite / privileged audit', '365 days'),
            'ATTACHMENT_UPLOAD_ATTEMPT_TTL_HOURS': (24, 'Upload-attempt metadata', '24 hours'),
            'ACCOUNT_DELETION_GRACE_DAYS': (7, 'Scheduled account deletion', '7-day grace period'),
            'AI_USER_USAGE_RETENTION_DAYS': (90, 'User-linked AI usage', '90 days'),
            'AI_GLOBAL_USAGE_RETENTION_DAYS': (400, 'User-linked AI usage', '400 days'),
        }
        for setting, (value, row_label, claim) in expected.items():
            self.assertEqual(self.setting_default(setting), value, setting)
            self.assertIn(row_label, self.notice)
            self.assertIn(claim, self.notice)
            self.assertIn(claim, self.register)

        absolute_match = require_match(
            self,
            r"SESSION_ABSOLUTE_MAX_AGE_SECONDS\s*=\s*_nonnegative_int_env\(\s*"
            r"['\"]SESSION_ABSOLUTE_MAX_AGE_SECONDS['\"]\s*,\s*(\d+)\s*\*\s*24\s*\*\s*60\s*\*\s*60",
            self.backend_settings,
            'absolute session maximum',
        )
        self.assertEqual(int(absolute_match.group(1)), 30)
        self.assertRegex(self.backend_settings, r'SESSION_COOKIE_AGE\s*=\s*14\s*\*\s*24\s*\*\s*60\s*\*\s*60')
        self.assertIn('14-day sliding cookie lifetime, capped at 30 days', self.notice)
        self.assertIn('14-day sliding cookie, absolute maximum 30 days', self.register)

    def test_backup_rotation_claim_matches_the_script(self):
        keep = require_match(
            self,
            r'^KEEP="\$\{KEEP:-(\d+)\}"$',
            self.backup,
            'database-backup retention',
        ).group(1)
        self.assertEqual(keep, '7')
        self.assertIn('newest 7 daily local backups', self.notice)
        self.assertIn('Newest 7 daily dumps', self.register)

    def test_all_verified_destinations_and_open_decisions_are_named(self):
        for term in ('NVIDIA', 'mailcow', 'Cloudflare', 'ClamAV', 'document parser'):
            self.assertIn(term, self.notice)
            self.assertIn(term, self.register)
        for gap in (
            'operator/controller identity',
            'legal basis',
            'production entitlement',
            'dedicated privacy contact',
        ):
            self.assertIn(gap, self.notice)

    def test_notice_is_not_misrepresented_as_blanket_consent(self):
        self.assertIn('it is not legal advice, a consent', self.notice)
        self.assertIn('does not record a blanket\nprivacy consent', self.register)
        self.assertIn('No dedicated privacy contact is currently published', self.notice)

    def test_external_notice_links_isolate_the_opener(self):
        external_links = re.findall(r'<a\s+href="https://[^>]+>', self.notice)
        self.assertGreaterEqual(len(external_links), 2)
        for link in external_links:
            self.assertIn('target="_blank"', link)
            self.assertIn('rel="noreferrer"', link)

    def test_ci_runs_the_privacy_contract(self):
        self.assertIn('python ../scripts/test_privacy_notice_contract.py', self.ci)


if __name__ == '__main__':
    unittest.main()
