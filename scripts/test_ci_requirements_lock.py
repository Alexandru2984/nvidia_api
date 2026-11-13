#!/usr/bin/env python3
"""Regressions for the hash-locked backend CI environment."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_ci_requirements_lock as checker


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "backend/requirements.txt"
DEVELOPMENT = ROOT / "backend/requirements-dev.txt"
RUNTIME_LOCK = ROOT / "backend/requirements.lock"
CI_LOCK = ROOT / "backend/requirements-ci.lock"
AUDIT_LOCK = ROOT / "backend/requirements-audit.lock"
WORKFLOW = ROOT / ".github/workflows/ci.yml"


class CiRequirementsLockTests(unittest.TestCase):
    def test_committed_ci_lock_is_exact_runtime_plus_test_closure(self):
        self.assertEqual(
            checker.check(REQUIREMENTS, DEVELOPMENT, RUNTIME_LOCK, CI_LOCK),
            (24, 2, 3),
        )

    def test_rejects_runtime_hash_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "ci.lock"
            content = CI_LOCK.read_text(encoding="utf-8")
            changed.write_text(content.replace("e8667a09", "f8667a09", 1), encoding="utf-8")
            with self.assertRaises(checker.CiLockError):
                checker.check(REQUIREMENTS, DEVELOPMENT, RUNTIME_LOCK, changed)

    def test_rejects_missing_or_unexpected_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = CI_LOCK.read_text(encoding="utf-8")
            missing = root / "missing.lock"
            missing.write_text(
                "\n".join(line for line in content.splitlines() if not line.startswith("pluggy=="))
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(checker.CiLockError):
                checker.check(REQUIREMENTS, DEVELOPMENT, RUNTIME_LOCK, missing)

            extra = root / "extra.lock"
            extra.write_text(
                content + "z-extra==1 --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(checker.CiLockError):
                checker.check(REQUIREMENTS, DEVELOPMENT, RUNTIME_LOCK, extra)

    def test_rejects_direct_test_version_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            changed = Path(directory) / "ci.lock"
            content = CI_LOCK.read_text(encoding="utf-8")
            changed.write_text(content.replace("pytest==9.1.1", "pytest==9.1.0"), encoding="utf-8")
            with self.assertRaises(checker.CiLockError):
                checker.check(REQUIREMENTS, DEVELOPMENT, RUNTIME_LOCK, changed)

    def test_committed_audit_lock_has_exact_reviewed_closure(self):
        self.assertEqual(checker.check_audit_lock(AUDIT_LOCK), 28)

    def test_rejects_audit_tool_version_or_package_set_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = AUDIT_LOCK.read_text(encoding="utf-8")

            changed = root / "changed.lock"
            changed.write_text(
                content.replace("pip_audit==2.10.1", "pip_audit==2.10.0"),
                encoding="utf-8",
            )
            with self.assertRaises(checker.CiLockError):
                checker.check_audit_lock(changed)

            expanded = root / "expanded.lock"
            expanded.write_text(
                content + "z-extra==1 --hash=sha256:" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(checker.CiLockError):
                checker.check_audit_lock(expanded)

    def test_workflow_installs_only_the_hash_locked_ci_environment(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "--disable-pip-version-check --only-binary=:all: --require-hashes",
            workflow,
        )
        self.assertIn("-r requirements-ci.lock", workflow)
        self.assertIn("-r requirements-audit.lock", workflow)
        self.assertIn("check_ci_requirements_lock.py", workflow)
        self.assertIn("-r requirements-ci.lock --progress-spinner off", workflow)
        self.assertIn("-r requirements-audit.lock --progress-spinner off", workflow)
        self.assertIn("${RUNNER_TEMP}/aichat-pip-audit", workflow)
        self.assertNotIn("pip install pip-audit", workflow)
        self.assertNotIn("pip install -r requirements.txt", workflow)
        self.assertNotIn("pip install -r requirements-dev.txt", workflow)
        self.assertLess(
            workflow.index("check_ci_requirements_lock.py"),
            workflow.index("-r requirements-ci.lock"),
        )


if __name__ == "__main__":
    unittest.main()
