#!/usr/bin/env python3
"""Regressions for the untrusted-code and credential boundary in CI."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class CiTrustBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_every_checkout_refuses_persisted_credentials(self):
        checkout_count = len(re.findall(r"^\s+- uses: actions/checkout@", self.workflow, re.M))
        self.assertEqual(checkout_count, 2)
        self.assertEqual(self.workflow.count("persist-credentials: false"), checkout_count)
        self.assertNotIn("persist-credentials: true", self.workflow)

    def test_jobs_have_bounded_execution_time(self):
        self.assertEqual(self.workflow.count("timeout-minutes:"), 2)
        self.assertIn("timeout-minutes: 20", self.workflow)
        self.assertIn("timeout-minutes: 30", self.workflow)

    def test_frontend_install_cannot_run_package_lifecycle_scripts(self):
        self.assertIn(
            "npm ci --ignore-scripts --no-audit --no-fund",
            self.workflow,
        )
        self.assertNotRegex(self.workflow, r"run:\s+npm ci\s*$")
        self.assertIn("NPM_CONFIG_IGNORE_SCRIPTS: 'true'", self.workflow)

    def test_frontend_commands_cannot_fall_back_to_remote_npx_packages(self):
        self.assertNotRegex(self.workflow, r"run:\s+npx\s")
        self.assertIn("run: npm run lint", self.workflow)
        self.assertIn(
            "run: node_modules/.bin/playwright install --with-deps chromium",
            self.workflow,
        )
        self.assertIn("run: npm run test:e2e", self.workflow)

    def test_python_installs_fail_closed_without_command_line_flags(self):
        for required in (
            "PIP_CONFIG_FILE: /dev/null",
            "PIP_NO_INPUT: '1'",
            "PIP_ONLY_BINARY: ':all:'",
            "PIP_REQUIRE_HASHES: '1'",
        ):
            self.assertIn(required, self.workflow)
        self.assertEqual(self.workflow.count("--disable-pip --strict -r"), 3)

    def test_dependency_gates_precede_project_code_execution(self):
        backend_audit = self.workflow.index("- name: Audit locked Python environments")
        backend_install = self.workflow.index("- name: Install dependencies")
        django = self.workflow.index("- name: Django system checks")
        self.assertLess(backend_audit, backend_install)
        self.assertLess(backend_install, django)

        frontend = self.workflow.index("  frontend:")
        frontend_install = self.workflow.index("- name: Install dependencies", frontend)
        vulnerability_audit = self.workflow.index("- name: Audit dependencies", frontend)
        signature_audit = self.workflow.index(
            "- name: Verify registry signatures and provenance", frontend
        )
        lint = self.workflow.index("- name: Lint", frontend)
        self.assertLess(frontend_install, vulnerability_audit)
        self.assertLess(vulnerability_audit, signature_audit)
        self.assertLess(signature_audit, lint)


if __name__ == "__main__":
    unittest.main()
