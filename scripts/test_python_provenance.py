#!/usr/bin/env python3
"""Offline regressions for the reviewed PyPI provenance gate."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/verify_python_provenance.py"
PRODUCTION_LOCK = ROOT / "backend/requirements.lock"
TOOL_LOCK = ROOT / "backend/requirements-provenance.lock"
POLICY = ROOT / "backend/python-provenance-policy.json"
CI = ROOT / ".github/workflows/ci.yml"

SPEC = importlib.util.spec_from_file_location("verify_python_provenance", SCRIPT)
assert SPEC and SPEC.loader
provenance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = provenance
SPEC.loader.exec_module(provenance)


class FakeResponse:
    def __init__(self, status: int, content: bytes, declared: str | None = None):
        self.status_code = status
        self.content = content
        self.headers = {} if declared is None else {"Content-Length": declared}
        self.closed = False

    def iter_content(self, chunk_size: int):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset:offset + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.call = None

    def get(self, url: str, **kwargs):
        self.call = (url, kwargs)
        return self.response


class PythonProvenanceTests(unittest.TestCase):
    def test_committed_policy_exactly_covers_the_24_wheel_lock(self):
        wheels = provenance.parse_lock(PRODUCTION_LOCK)
        policy = provenance.parse_policy(POLICY, wheels)
        self.assertEqual(len(wheels), 24)
        self.assertEqual(len(policy), 24)
        self.assertEqual(sum(value is not None for value in policy.values()), 12)
        self.assertEqual(sum(value is None for value in policy.values()), 12)
        self.assertEqual(
            policy["cryptography"],
            {
                "environment": None,
                "kind": "GitHub",
                "repository": "pyca/cryptography",
                "workflow": "pypi-publish.yml",
            },
        )

    def test_verifier_dependency_lock_is_exact_sorted_and_single_artifact(self):
        entries = []
        for raw in TOOL_LOCK.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = provenance.LOCK_RE.fullmatch(line)
            self.assertIsNotNone(match, line)
            entries.append((
                provenance.canonicalize(match.group("name")),
                match.group("version"),
                match.group("digest"),
            ))
        self.assertEqual(len(entries), 32)
        self.assertEqual([item[0] for item in entries], sorted(item[0] for item in entries))
        self.assertEqual(len({item[0] for item in entries}), len(entries))
        self.assertIn(
            ("pypi-attestations", provenance.EXPECTED_LIBRARY_VERSION,
             "c022f7bc771545463fdcbb019160b86b87a6048c9a9edb7d541824593d64a1c8"),
            entries,
        )

    def test_lock_and_policy_fail_closed_on_duplicates_drift_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lock"
            lock.write_text(
                "demo==1 --hash=sha256:" + "a" * 64 + "\n"
                "Demo==1 --hash=sha256:" + "b" * 64 + "\n",
                encoding="ascii",
            )
            with self.assertRaises(provenance.ProvenanceError):
                provenance.parse_lock(lock)

            lock.write_text(
                "demo==1 --hash=sha256:" + "a" * 64 + "\n",
                encoding="ascii",
            )
            wheels = provenance.parse_lock(lock)
            policy = root / "policy"
            policy.write_text(json.dumps({"version": 1, "packages": {}}), encoding="utf-8")
            with self.assertRaises(provenance.ProvenanceError):
                provenance.parse_policy(policy, wheels)

            policy.write_text(
                '{"version":1,"version":1,"packages":{"demo":null}}',
                encoding="utf-8",
            )
            with self.assertRaises(provenance.ProvenanceError):
                provenance.parse_policy(policy, wheels)

            link = root / "link"
            link.symlink_to(lock)
            with self.assertRaises(provenance.ProvenanceError):
                provenance.parse_lock(link)

    def test_artifact_selection_binds_exact_hash_wheel_type_host_and_yank_state(self):
        wheel = provenance.LockedWheel("demo", "demo", "1", "a" * 64)
        artifact = {
            "digests": {"sha256": "a" * 64},
            "filename": "demo-1-py3-none-any.whl",
            "packagetype": "bdist_wheel",
            "url": "https://files.pythonhosted.org/packages/demo-1-py3-none-any.whl",
            "yanked": False,
        }
        self.assertEqual(provenance.select_artifact({"urls": [artifact]}, wheel), artifact)
        for mutation in (
            {"yanked": True},
            {"packagetype": "sdist"},
            {"url": "https://example.com/demo.whl"},
            {"filename": "../demo.whl"},
        ):
            candidate = artifact | mutation
            with self.subTest(mutation=mutation), self.assertRaises(provenance.ProvenanceError):
                provenance.select_artifact({"urls": [candidate]}, wheel)

    def test_network_reader_refuses_status_and_declared_or_streamed_overflow(self):
        response = FakeResponse(302, b"")
        with self.assertRaises(provenance.ProvenanceError):
            provenance.bounded_get(FakeSession(response), "https://pypi.org/a", 4, accept="x")
        self.assertTrue(response.closed)

        response = FakeResponse(200, b"12345", declared="5")
        with self.assertRaises(provenance.ProvenanceError):
            provenance.bounded_get(FakeSession(response), "https://pypi.org/a", 4, accept="x")
        self.assertTrue(response.closed)

        response = FakeResponse(200, b"12345")
        with self.assertRaises(provenance.ProvenanceError):
            provenance.bounded_get(FakeSession(response), "https://pypi.org/a", 4, accept="x")
        self.assertTrue(response.closed)

    def test_ci_uses_python_314_and_an_isolated_hash_locked_verifier(self):
        ci = CI.read_text(encoding="utf-8")
        self.assertIn("python-version: '3.14'", ci)
        for required in (
            "requirements-provenance.lock",
            "python -m venv /tmp/aichat-pypi-provenance",
            "/tmp/aichat-pypi-provenance/bin/python -m pip install",
            "--only-binary=:all: --require-hashes",
            "verify_python_provenance.py",
            "python-provenance-policy.json",
            "pip-audit -r requirements-provenance.lock",
            "python ../scripts/test_python_provenance.py",
        ):
            self.assertIn(required, ci)

    def test_verifier_calls_cryptographic_api_and_requires_publish_predicate(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("attestation.verify(expected, distribution)", source)
        self.assertIn("provenance.attestation_bundles[0].publisher != expected", source)
        self.assertIn("PUBLISH_PREDICATE not in predicates", source)
        self.assertIn("hashlib.sha256(wheel_bytes).hexdigest()", source)
        self.assertNotIn("allow_redirects=True", source)


if __name__ == "__main__":
    unittest.main()
