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

    def test_frontend_commands_cannot_fall_back_to_remote_npx_packages(self):
        self.assertNotRegex(self.workflow, r"run:\s+npx\s")
        self.assertIn("run: npm run lint", self.workflow)
        self.assertIn(
            "run: node_modules/.bin/playwright install --with-deps chromium",
            self.workflow,
        )
        self.assertIn("run: npm run test:e2e", self.workflow)

    def test_regression_suite_runs_before_dependency_audits(self):
        regression = self.workflow.index("python ../scripts/test_ci_trust_boundary.py")
        backend_audit = self.workflow.index("- name: Audit runtime dependencies")
        frontend_audit = self.workflow.index("- name: Audit dependencies")
        self.assertLess(regression, backend_audit)
        self.assertLess(backend_audit, frontend_audit)


if __name__ == "__main__":
    unittest.main()
