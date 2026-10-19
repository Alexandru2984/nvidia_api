#!/usr/bin/env python3
"""Fail closed if automated dependency updates bypass the review boundary."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".github/dependabot.yml"
POLICY = ROOT / "docs/DEPENDENCY_UPDATE_POLICY.md"


class DependencyUpdatePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = CONFIG.read_text(encoding="utf-8")
        cls.policy = POLICY.read_text(encoding="utf-8")

    def test_exact_ecosystem_directories_are_covered(self) -> None:
        pairs = re.findall(
            r'package-ecosystem: "([^"]+)"\n\s+directory: "([^"]+)"',
            self.config,
        )
        self.assertEqual(
            pairs,
            [("npm", "/frontend"), ("pip", "/backend"), ("github-actions", "/")],
        )

    def test_updates_are_bounded_and_security_updates_are_not_redirected(self) -> None:
        self.assertEqual(self.config.count('interval: "weekly"'), 3)
        self.assertEqual(self.config.count('timezone: "Europe/Bucharest"'), 3)
        self.assertEqual(self.config.count("open-pull-requests-limit:"), 3)
        self.assertNotIn("target-branch:", self.config)
        self.assertNotIn("registries:", self.config)
        self.assertNotIn("insecure-external-code-execution:", self.config)

    def test_config_grants_no_merge_or_workflow_authority(self) -> None:
        lowered = self.config.lower()
        for forbidden in ("automerge", "auto-merge", "pull_request_target", "permissions:"):
            self.assertNotIn(forbidden, lowered)

    def test_review_policy_keeps_hash_ci_and_manual_deploy_gates(self) -> None:
        for required in (
            "auto-merged or deployed",
            "requirements.lock",
            "SHA-256",
            "human review",
            "green CI",
            "commit-bound release",
        ):
            self.assertIn(required, self.policy)


if __name__ == "__main__":
    unittest.main()
