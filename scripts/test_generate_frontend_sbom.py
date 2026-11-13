#!/usr/bin/env python3
"""Regressions for the deterministic frontend CycloneDX SBOM."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import generate_frontend_sbom as sbom


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "0123456789abcdef0123456789abcdef01234567"
TREE = "89abcdef0123456789abcdef0123456789abcdef"


def integrity(byte: int) -> str:
    return "sha512-" + base64.b64encode(bytes([byte]) * 64).decode("ascii")


class FrontendSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.lock = Path(self.temporary.name) / "package-lock.json"
        self.document = {
            "name": "frontend",
            "version": "0.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {"name": "frontend", "version": "0.0.0"},
                "node_modules/example": {
                    "version": "1.2.3",
                    "resolved": "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
                    "integrity": integrity(1),
                    "license": "MIT",
                },
                "node_modules/parent/node_modules/@scope/tool": {
                    "version": "4.5.6",
                    "resolved": "https://registry.npmjs.org/@scope/tool/-/tool-4.5.6.tgz",
                    "integrity": integrity(2),
                    "license": "Apache-2.0",
                    "dev": True,
                    "optional": True,
                },
            },
        }
        self.write_lock()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_lock(self) -> None:
        self.lock.write_text(json.dumps(self.document) + "\n", encoding="utf-8")

    def test_is_deterministic_and_records_hashes_licenses_and_paths(self) -> None:
        first = sbom.build_sbom(self.lock, COMMIT, TREE)
        second = sbom.build_sbom(self.lock, COMMIT, TREE)
        self.assertEqual(sbom.render_sbom(first), sbom.render_sbom(second))
        self.assertEqual(first["specVersion"], "1.7")
        self.assertEqual(len(first["components"]), 2)
        scoped = first["components"][1]
        self.assertEqual(scoped["purl"], "pkg:npm/%40scope/tool@4.5.6")
        self.assertEqual(scoped["hashes"], [{"alg": "SHA-512", "content": "02" * 64}])
        self.assertEqual(scoped["licenses"], [{"expression": "Apache-2.0"}])

    def test_records_exact_source_and_lock_identity(self) -> None:
        document = sbom.build_sbom(self.lock, COMMIT, TREE)
        properties = {
            item["name"]: item["value"] for item in document["metadata"]["properties"]
        }
        self.assertEqual(properties["aichat:source-commit"], COMMIT)
        self.assertEqual(properties["aichat:frontend-tree"], TREE)
        self.assertEqual(
            properties["aichat:package-lock-sha256"],
            hashlib.sha256(self.lock.read_bytes()).hexdigest(),
        )

    def test_exact_validator_rejects_tampering(self) -> None:
        document = sbom.build_sbom(self.lock, COMMIT, TREE)
        tampered = copy.deepcopy(document)
        tampered["components"][0]["version"] = "9.9.9"
        with self.assertRaises(sbom.FrontendSbomError):
            sbom.validate_sbom(tampered, self.lock, COMMIT, TREE)

    def test_rejects_duplicate_json_keys(self) -> None:
        self.lock.write_text(
            '{"lockfileVersion":3,"lockfileVersion":3,"packages":{}}\n',
            encoding="utf-8",
        )
        with self.assertRaises(sbom.FrontendSbomError):
            sbom.build_sbom(self.lock, COMMIT, TREE)

    def test_rejects_wrong_registry_or_integrity(self) -> None:
        package = self.document["packages"]["node_modules/example"]
        package["resolved"] = "https://evil.invalid/example.tgz"
        self.write_lock()
        with self.assertRaises(sbom.FrontendSbomError):
            sbom.build_sbom(self.lock, COMMIT, TREE)
        package["resolved"] = "https://registry.npmjs.org/example/-/example.tgz"
        package["integrity"] = "sha256-deadbeef"
        self.write_lock()
        with self.assertRaises(sbom.FrontendSbomError):
            sbom.build_sbom(self.lock, COMMIT, TREE)

    def test_rejects_package_name_path_or_license_drift(self) -> None:
        package = self.document["packages"]["node_modules/example"]
        package["name"] = "different"
        self.write_lock()
        with self.assertRaises(sbom.FrontendSbomError):
            sbom.build_sbom(self.lock, COMMIT, TREE)
        package.pop("name")
        package["license"] = "SEE LICENSE IN file"
        self.write_lock()
        with self.assertRaises(sbom.FrontendSbomError):
            sbom.build_sbom(self.lock, COMMIT, TREE)

    def test_committed_lock_has_complete_exact_inventory(self) -> None:
        packages, _ = sbom.parse_lock(ROOT / "frontend/package-lock.json")
        self.assertEqual(len(packages), 276)
        self.assertTrue(all(len(package.digest) == 128 for package in packages))
        self.assertEqual(
            {package.license for package in packages}, sbom.ALLOWED_LICENSES,
        )

    def test_build_deploy_and_ci_require_exact_sbom_validation(self) -> None:
        build = (ROOT / "scripts/build_frontend_release.sh").read_text(encoding="utf-8")
        deploy = (ROOT / "scripts/deploy_frontend.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "scripts/release_rollback_drill.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for source in (build, deploy, workflow):
            self.assertIn("generate_frontend_sbom.py", source)
            self.assertIn(".release-sbom.cdx.json", source)
        self.assertIn("active frontend release has no embedded SBOM", rollback)
        self.assertIn("--check dist/.release-sbom.cdx.json", workflow)


if __name__ == "__main__":
    unittest.main()
