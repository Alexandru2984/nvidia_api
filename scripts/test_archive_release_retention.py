#!/usr/bin/env python3
"""Regression tests for safe immutable-release retention."""

from __future__ import annotations

import hashlib
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from archive_release_retention import (
    ReleaseFamily,
    RetentionError,
    archive_candidate,
    plan_family,
)


class ReleaseRetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.releases = self.root / "releases"
        self.releases.mkdir(mode=0o755)
        self.live = self.root / "current"
        self.family = ReleaseFamily(
            "test",
            self.releases,
            self.live,
            self.root / "archive",
            100,
            1024 * 1024,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def release(self, sequence: int) -> Path:
        path = self.releases / f"release-20261014T12000{sequence}_{sequence:09d}"
        path.mkdir(mode=0o755)
        payload = path / "payload.txt"
        payload.write_text(f"release {sequence}\n", encoding="utf-8")
        payload.chmod(0o644)
        return path

    def plan(self, keep_inactive: int = 2) -> dict[str, object]:
        return plan_family(
            self.family,
            keep_inactive,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )

    def test_retains_active_and_two_newest_inactive(self) -> None:
        releases = [self.release(index) for index in range(5)]
        self.live.symlink_to(releases[-1])
        plan = self.plan()
        self.assertEqual(plan["retained"], [releases[-1], releases[-2], releases[-3]])
        self.assertEqual(plan["candidates"], [releases[0], releases[1]])

    def test_never_selects_an_old_active_release(self) -> None:
        releases = [self.release(index) for index in range(5)]
        self.live.symlink_to(releases[0])
        plan = self.plan()
        self.assertIn(releases[0], plan["retained"])
        self.assertNotIn(releases[0], plan["candidates"])

    def test_legacy_tree_is_always_selected(self) -> None:
        active = self.release(1)
        self.live.symlink_to(active)
        legacy = self.releases / "legacy-20261014T110000_000000001"
        legacy.mkdir(mode=0o755)
        (legacy / "index.html").write_text("legacy\n", encoding="utf-8")
        plan = self.plan()
        self.assertEqual(plan["candidates"], [legacy])

    def test_rejects_symlink_inside_candidate(self) -> None:
        releases = [self.release(index) for index in range(3)]
        self.live.symlink_to(releases[-1])
        (releases[0] / "unsafe").symlink_to("/etc/passwd")
        with self.assertRaises(RetentionError):
            self.plan(keep_inactive=1)

    def test_requires_at_least_one_rollback(self) -> None:
        active = self.release(1)
        self.live.symlink_to(active)
        with self.assertRaises(RetentionError):
            self.plan(keep_inactive=0)

    def test_archive_is_private_verified_and_recoverable(self) -> None:
        candidate = self.release(1)
        archive = archive_candidate(
            self.family,
            candidate,
            expected_uid=os.getuid(),
            expected_gid=os.getgid(),
        )
        self.assertFalse(candidate.exists())
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        digest_path = archive.with_suffix(archive.suffix + ".sha256")
        expected = digest_path.read_text(encoding="ascii").split()[0]
        self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), expected)
        with tarfile.open(archive, mode="r:gz") as retained:
            self.assertIn("test/release-20261014T120001_000000001/payload.txt", retained.getnames())


if __name__ == "__main__":
    unittest.main()
