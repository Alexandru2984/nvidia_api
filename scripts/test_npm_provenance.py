#!/usr/bin/env python3
"""Offline regressions for the reviewed npm provenance gate."""

from __future__ import annotations

import base64
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

import verify_npm_provenance as provenance
from generate_frontend_sbom import parse_lock


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "frontend/package-lock.json"
POLICY = ROOT / "frontend/npm-provenance-policy.tsv"
CI = ROOT / ".github/workflows/ci.yml"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def integrity(byte: int = 1) -> str:
    return "sha512-" + base64.b64encode(bytes([byte]) * 64).decode("ascii")


def encode(payload: dict[str, object]) -> str:
    rendered = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.b64encode(rendered).decode("ascii")


class NpmProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.lock = self.root / "package-lock.json"
        self.policy = self.root / "policy.tsv"
        self.location = "node_modules/example"
        self.repository = "https://github.com/example/example"
        self.workflow = ".github/workflows/release.yml"
        self.ref = "refs/heads/main"
        self.repository_id = "123"
        self.owner_id = "456"
        self.write_lock(self.location)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_lock(self, location: str) -> None:
        name = location.rsplit("node_modules/", 1)[1]
        document = {
            "name": "frontend",
            "version": "0.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {"name": "frontend", "version": "0.0.0"},
                location: {
                    "version": "1.2.3",
                    "resolved": f"https://registry.npmjs.org/{name}/-/{name}-1.2.3.tgz",
                    "integrity": integrity(),
                    "license": "MIT",
                },
            },
        }
        self.lock.write_text(json.dumps(document) + "\n", encoding="utf-8")

    def package(self):
        packages, _ = parse_lock(self.lock)
        self.assertEqual(len(packages), 1)
        return packages[0]

    def write_policy(self, package) -> None:
        self.policy.write_text(
            "# location\tname\tversion\tsha512\trepository\tworkflow\tref"
            "\trepository_id\towner_id\tsource_commit\n"
            + "\t".join((
                package.path,
                package.name,
                package.version,
                package.digest,
                self.repository,
                self.workflow,
                self.ref,
                self.repository_id,
                self.owner_id,
                COMMIT,
            ))
            + "\n",
            encoding="utf-8",
        )

    def report(self, package, *, legacy: bool = False) -> dict[str, object]:
        subject = [{"name": package.purl, "digest": {"sha512": package.digest}}]
        publish = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": subject,
            "predicateType": provenance.PUBLISH_PREDICATE,
            "predicate": {
                "name": package.name,
                "version": package.version,
                "registry": provenance.REGISTRY,
            },
        }
        if legacy:
            source_uri = f"git+{self.repository}@{self.ref}"
            provenance_predicate = provenance.SLSA_V02_PREDICATE
            slsa = {
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": subject,
                "predicateType": provenance_predicate,
                "predicate": {
                    "buildType": provenance.SLSA_V02_BUILD_TYPE,
                    "builder": {"id": provenance.SLSA_V02_BUILDER},
                    "invocation": {
                        "configSource": {
                            "uri": source_uri,
                            "digest": {"sha1": COMMIT},
                            "entryPoint": self.workflow,
                        },
                        "parameters": {},
                        "environment": {
                            "GITHUB_EVENT_NAME": "push",
                            "GITHUB_REF": self.ref,
                            "GITHUB_REPOSITORY": "example/example",
                            "GITHUB_REPOSITORY_ID": self.repository_id,
                            "GITHUB_REPOSITORY_OWNER_ID": self.owner_id,
                            "GITHUB_RUN_ATTEMPT": "1",
                            "GITHUB_RUN_ID": "789",
                            "GITHUB_SHA": COMMIT,
                            "GITHUB_WORKFLOW_REF": (
                                f"example/example/{self.workflow}@{self.ref}"
                            ),
                            "GITHUB_WORKFLOW_SHA": COMMIT,
                        },
                    },
                    "metadata": {
                        "buildInvocationId": "789-1",
                        "completeness": {
                            "parameters": False,
                            "environment": False,
                            "materials": False,
                        },
                        "reproducible": False,
                    },
                    "materials": [{"uri": source_uri, "digest": {"sha1": COMMIT}}],
                },
            }
        else:
            provenance_predicate = provenance.SLSA_V1_PREDICATE
            slsa = {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": subject,
                "predicateType": provenance_predicate,
                "predicate": {
                    "buildDefinition": {
                        "buildType": provenance.SLSA_V1_BUILD_TYPE,
                        "externalParameters": {
                            "workflow": {
                                "ref": self.ref,
                                "repository": self.repository,
                                "path": self.workflow,
                            },
                        },
                        "internalParameters": {
                            "github": {
                                "event_name": "push",
                                "repository_id": self.repository_id,
                                "repository_owner_id": self.owner_id,
                            },
                        },
                        "resolvedDependencies": [{
                            "uri": f"git+{self.repository}@{self.ref}",
                            "digest": {"gitCommit": COMMIT},
                        }],
                    },
                    "runDetails": {
                        "builder": {"id": provenance.SLSA_V1_BUILDER},
                        "metadata": {
                            "invocationId": f"{self.repository}/actions/runs/789/attempts/1",
                        },
                    },
                },
            }
        bundles = [
            {
                "predicateType": provenance.PUBLISH_PREDICATE,
                "bundle": {"dsseEnvelope": {"payload": encode(publish)}},
            },
            {
                "predicateType": provenance_predicate,
                "bundle": {"dsseEnvelope": {"payload": encode(slsa)}},
            },
        ]
        return {
            "invalid": [],
            "missing": [],
            "verified": [{
                "name": package.name,
                "version": package.version,
                "location": package.path,
                "registry": f"{provenance.REGISTRY}/",
                "attestations": {
                    "url": (
                        f"{provenance.REGISTRY}/-/npm/v1/attestations/"
                        f"{package.name}@{package.version}"
                    ),
                    "provenance": {"predicateType": provenance_predicate},
                },
                "attestationBundles": bundles,
            }],
        }

    @staticmethod
    def payload(report: dict[str, object], index: int) -> dict[str, object]:
        encoded = report["verified"][0]["attestationBundles"][index]["bundle"][
            "dsseEnvelope"
        ]["payload"]
        return json.loads(base64.b64decode(encoded))

    @staticmethod
    def replace_payload(
        report: dict[str, object], index: int, payload: dict[str, object]
    ) -> None:
        report["verified"][0]["attestationBundles"][index]["bundle"][
            "dsseEnvelope"
        ]["payload"] = encode(payload)

    def test_valid_v1_fixture_is_bound_to_lock_and_policy(self) -> None:
        package = self.package()
        self.write_policy(package)
        self.assertEqual(
            provenance.verify(self.report(package), self.lock, self.policy),
            (1, 0),
        )

    def test_exact_legacy_v02_fixture_is_supported_only_at_reviewed_location(self) -> None:
        self.location = next(iter(provenance.LEGACY_PROVENANCE_BY_LOCATION))
        self.write_lock(self.location)
        package = self.package()
        self.write_policy(package)
        report = self.report(package, legacy=True)
        self.assertEqual(provenance.verify(report, self.lock, self.policy), (1, 0))
        report["verified"][0]["location"] = "node_modules/example"
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)

    def test_subject_digest_and_package_version_tampering_fail(self) -> None:
        package = self.package()
        self.write_policy(package)
        report = self.report(package)
        publish = self.payload(report, 0)
        publish["subject"][0]["digest"]["sha512"] = "f" * 128
        self.replace_payload(report, 0, publish)
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)

        report = self.report(package)
        report["verified"][0]["version"] = "9.9.9"
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)

    def test_publisher_workflow_ref_ids_and_source_drift_fail(self) -> None:
        package = self.package()
        self.write_policy(package)
        mutations = (
            ("externalParameters", "workflow", "path", ".github/workflows/other.yml"),
            ("internalParameters", "github", "repository_id", "999"),
            ("internalParameters", "github", "repository_owner_id", "999"),
            ("internalParameters", "github", "event_name", "release"),
            ("resolvedDependencies", 0, "digest", {"gitCommit": "f" * 40}),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                report = self.report(package)
                slsa = self.payload(report, 1)
                target = slsa["predicate"]["buildDefinition"]
                for key in mutation[:-2]:
                    target = target[key]
                target[mutation[-2]] = mutation[-1]
                self.replace_payload(report, 1, slsa)
                with self.assertRaises(provenance.NpmProvenanceError):
                    provenance.verify(report, self.lock, self.policy)

        report = self.report(package)
        slsa = self.payload(report, 1)
        build = slsa["predicate"]["buildDefinition"]
        build["externalParameters"]["workflow"]["repository"] = (
            "https://github.com/example/other"
        )
        build["resolvedDependencies"][0]["uri"] = (
            f"git+https://github.com/example/other@{self.ref}"
        )
        slsa["predicate"]["runDetails"]["metadata"]["invocationId"] = (
            "https://github.com/example/other/actions/runs/789/attempts/1"
        )
        self.replace_payload(report, 1, slsa)
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)

        report = self.report(package)
        slsa = self.payload(report, 1)
        workflow = slsa["predicate"]["buildDefinition"]["externalParameters"]["workflow"]
        workflow["ref"] = "refs/tags/other"
        resolved = slsa["predicate"]["buildDefinition"]["resolvedDependencies"][0]
        resolved["uri"] = f"git+{self.repository}@refs/tags/other"
        self.replace_payload(report, 1, slsa)
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)

    def test_missing_invalid_new_or_removed_attestation_fails(self) -> None:
        package = self.package()
        self.write_policy(package)
        for key in ("missing", "invalid"):
            report = self.report(package)
            report[key] = [{"name": package.name}]
            with self.subTest(key=key), self.assertRaises(provenance.NpmProvenanceError):
                provenance.verify(report, self.lock, self.policy)
        report = self.report(package)
        report["verified"] = []
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)
        report = self.report(package)
        report["verified"].append(copy.deepcopy(report["verified"][0]))
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.verify(report, self.lock, self.policy)

    def test_duplicate_json_and_unsafe_or_duplicate_policy_fail(self) -> None:
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.read_report(io.BytesIO(b'{"invalid":[],"invalid":[]}'))
        package = self.package()
        self.write_policy(package)
        original = self.policy.read_text(encoding="utf-8")
        self.policy.write_text(original + original.splitlines()[-1] + "\n", encoding="utf-8")
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.parse_policy(self.policy)
        self.policy.unlink()
        self.policy.symlink_to(self.lock)
        with self.assertRaises(provenance.NpmProvenanceError):
            provenance.parse_policy(self.policy)

    def test_committed_policy_and_ci_gate_are_complete(self) -> None:
        packages, _ = parse_lock(LOCK)
        locked = {package.path: package for package in packages}
        policy = provenance.parse_policy(POLICY)
        self.assertEqual(len(packages), 276)
        self.assertEqual(len(policy), 58)
        for entry in policy:
            package = locked[entry.location]
            self.assertEqual(
                (entry.name, entry.version, entry.sha512),
                (package.name, package.version, package.digest),
            )
        self.assertEqual(
            set(provenance.LEGACY_PROVENANCE_BY_LOCATION),
            {"node_modules/@eslint-community/eslint-utils/node_modules/eslint-visitor-keys"},
        )
        self.assertLessEqual(
            set(provenance.NON_PUSH_EVENT_BY_LOCATION),
            {entry.location for entry in policy},
        )

        workflow = CI.read_text(encoding="utf-8")
        for required in (
            "npm audit signatures --json --include-attestations",
            "verify_npm_provenance.py",
            "npm-provenance-policy.tsv",
            "python ../scripts/test_npm_provenance.py",
        ):
            self.assertIn(required, workflow)


if __name__ == "__main__":
    unittest.main()
