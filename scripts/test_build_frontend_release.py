#!/usr/bin/env python3
"""Regression tests for the commit-bound, secret-free frontend build wrapper."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE_SCRIPT = Path(__file__).with_name("build_frontend_release.sh")


class FrontendReleaseBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "frontend").mkdir()
        (self.root / "fake-bin").mkdir()
        shutil.copy2(SOURCE_SCRIPT, self.root / "scripts/build_frontend_release.sh")
        (self.root / "frontend/.gitignore").write_text(
            "dist/\nnode_modules/\n*.local\n", encoding="utf-8"
        )
        (self.root / "frontend/package.json").write_text("{}\n", encoding="utf-8")
        (self.root / "frontend/source.jsx").write_text(
            "export const value = 1\n", encoding="utf-8"
        )
        fake_npm = self.root / "fake-bin/npm"
        fake_npm.write_text(
            """#!/bin/sh
set -eu
test "$1" = "--prefix"
frontend_dir=$2
mkdir -p "$frontend_dir/dist"
printf '<!doctype html>\n' > "$frontend_dir/dist/index.html"
""",
            encoding="utf-8",
        )
        fake_npm.chmod(0o755)
        self._run("git", "init", "--initial-branch=main")
        self._run("git", "config", "user.name", "Release Test")
        self._run("git", "config", "user.email", "release-test@example.invalid")
        self._run("git", "add", ".")
        self._run("git", "commit", "-m", "fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _run(
        self,
        *command: str,
        check: bool = True,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PATH"] = f"{self.root / 'fake-bin'}:{environment['PATH']}"
        environment.update(extra_environment or {})
        return subprocess.run(
            command,
            cwd=self.root,
            env=environment,
            check=check,
            capture_output=True,
            text=True,
        )

    def _build(
        self,
        *,
        check: bool = True,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return self._run(
            "scripts/build_frontend_release.sh",
            check=check,
            extra_environment=extra_environment,
        )

    def test_build_records_exact_commit_and_frontend_tree(self) -> None:
        result = self._build()
        commit = self._run("git", "rev-parse", "HEAD").stdout.strip()
        tree = self._run("git", "rev-parse", "HEAD:frontend").stdout.strip()
        self.assertEqual(
            (self.root / "frontend/dist/.release-commit").read_text().strip(),
            commit,
        )
        self.assertEqual(
            (self.root / "frontend/dist/.release-frontend-tree").read_text().strip(),
            tree,
        )
        self.assertIn(f"commit={commit} tree={tree}", result.stdout)

    def test_build_rejects_dirty_tracked_frontend_input(self) -> None:
        (self.root / "frontend/source.jsx").write_text(
            "export const value = 2\n", encoding="utf-8"
        )
        result = self._build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not committed", result.stderr)
        self.assertFalse((self.root / "frontend/dist").exists())

    def test_build_rejects_untracked_frontend_input(self) -> None:
        (self.root / "frontend/untracked.jsx").write_text("untracked\n", encoding="utf-8")
        result = self._build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not committed", result.stderr)

    def test_build_rejects_ignored_environment_input(self) -> None:
        (self.root / "frontend/.env.local").write_text(
            "VITE_PRIVATE_VALUE=must-not-enter-build\n", encoding="utf-8"
        )
        result = self._build(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ignored frontend input", result.stderr)
        self.assertFalse((self.root / "frontend/dist").exists())

    def test_build_rejects_ambient_vite_values(self) -> None:
        result = self._build(
            check=False,
            extra_environment={"VITE_PRIVATE_VALUE": "must-not-enter-build"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ambient VITE_*", result.stderr)
        self.assertFalse((self.root / "frontend/dist").exists())


if __name__ == "__main__":
    unittest.main()
