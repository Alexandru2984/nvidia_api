#!/usr/bin/env python3
"""Regression tests for the deterministic production Python SBOM."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from generate_python_sbom import SbomError, build_sbom, render_sbom, validate_sbom


COMMIT = "0123456789abcdef0123456789abcdef01234567"


class PythonSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.lock = self.root / "requirements.lock"
        self.lock.write_text(
            """Example_Package==2.0.1 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
another.package==1.4 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
""",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_is_deterministic_and_records_exact_wheel_hashes(self) -> None:
        first = build_sbom(self.lock, COMMIT)
        second = build_sbom(self.lock, COMMIT)
        self.assertEqual(render_sbom(first), render_sbom(second))
        self.assertEqual(first["specVersion"], "1.7")
        self.assertEqual(len(first["components"]), 2)
        component = first["components"][1]
        self.assertEqual(component["purl"], "pkg:pypi/example-package@2.0.1")
        self.assertEqual(component["hashes"][0]["content"], "a" * 64)

    def test_records_lock_digest_and_commit(self) -> None:
        document = build_sbom(self.lock, COMMIT)
        properties = {
            item["name"]: item["value"]
            for item in document["metadata"]["properties"]
        }
        self.assertEqual(properties["aichat:requirements-commit"], COMMIT)
        self.assertEqual(
            properties["aichat:requirements-lock-sha256"],
            hashlib.sha256(self.lock.read_bytes()).hexdigest(),
        )

    def test_exact_validator_rejects_component_tampering(self) -> None:
        document = build_sbom(self.lock, COMMIT)
        tampered = copy.deepcopy(document)
        tampered["components"][0]["version"] = "9.9.9"
        with self.assertRaises(SbomError):
            validate_sbom(tampered, self.lock, COMMIT)

    def test_rejects_short_commit(self) -> None:
        with self.assertRaises(SbomError):
            build_sbom(self.lock, "0123456")

    def test_rejects_multiple_or_missing_hashes(self) -> None:
        self.lock.write_text(
            "package==1 --hash=sha256:" + "a" * 64 + " --hash=sha256:" + "b" * 64 + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(SbomError):
            build_sbom(self.lock, COMMIT)

    def test_rendered_document_round_trips(self) -> None:
        document = build_sbom(self.lock, COMMIT)
        self.assertEqual(json.loads(render_sbom(document)), document)


if __name__ == "__main__":
    unittest.main()
