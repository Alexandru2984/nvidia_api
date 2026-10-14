#!/usr/bin/env python3
"""Regression tests for immutable GitHub Actions validation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from check_github_actions_pins import unpinned_actions


PIN = "0123456789abcdef0123456789abcdef01234567"


class GitHubActionsPinTests(unittest.TestCase):
    def check(self, workflow: str) -> list[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci.yml").write_text(workflow, encoding="utf-8")
            return unpinned_actions(root)

    def test_accepts_full_sha_local_and_container_actions(self) -> None:
        findings = self.check(
            f"""steps:
  - uses: actions/checkout@{PIN} # v4.4.0
  - uses: ./local-action
  - uses: docker://alpine:3.22
"""
        )
        self.assertEqual(findings, [])

    def test_rejects_moving_tag(self) -> None:
        findings = self.check("steps:\n  - uses: actions/checkout@v4\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("not pinned", findings[0])

    def test_rejects_branch_and_short_sha(self) -> None:
        findings = self.check(
            """steps:
  - uses: owner/action@main
  - uses: owner/action@0123456789ab
"""
        )
        self.assertEqual(len(findings), 2)

    def test_rejects_remote_action_without_ref(self) -> None:
        findings = self.check("steps:\n  - uses: owner/action\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("has no ref", findings[0])

    def test_requires_workflows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            findings = unpinned_actions(Path(directory))
        self.assertEqual(len(findings), 1)
        self.assertIn("no workflow files", findings[0])


if __name__ == "__main__":
    unittest.main()
