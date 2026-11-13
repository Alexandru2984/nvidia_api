#!/usr/bin/env python3
"""Pin npm-verified SLSA provenance to reviewed lock artifacts and identities."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from generate_frontend_sbom import LockedPackage, parse_lock


PUBLISH_PREDICATE = "https://github.com/npm/attestation/tree/main/specs/publish/v0.1"
SLSA_V1_PREDICATE = "https://slsa.dev/provenance/v1"
SLSA_V02_PREDICATE = "https://slsa.dev/provenance/v0.2"
SLSA_V1_BUILD_TYPE = "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"
SLSA_V1_BUILDER = "https://github.com/actions/runner/github-hosted"
SLSA_V02_BUILD_TYPE = "https://github.com/npm/cli/gha/v2"
SLSA_V02_BUILDER = "https://github.com/actions/runner"
REGISTRY = "https://registry.npmjs.org"
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_POLICY_BYTES = 128 * 1024
HEX512 = re.compile(r"[0-9a-f]{128}")
COMMIT = re.compile(r"[0-9a-f]{40}")
IDENTIFIER = re.compile(r"[1-9][0-9]{0,19}")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9._-]+\.ya?ml")
REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9._/+@-]{1,200}")
REPOSITORY = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
LEGACY_PROVENANCE_BY_LOCATION = {
    "node_modules/@eslint-community/eslint-utils/node_modules/eslint-visitor-keys":
        SLSA_V02_PREDICATE,
}
NON_PUSH_EVENT_BY_LOCATION = {
    "node_modules/@babel/generator": "workflow_dispatch",
    "node_modules/@babel/parser": "workflow_dispatch",
    "node_modules/@babel/traverse": "workflow_dispatch",
    "node_modules/@babel/types": "workflow_dispatch",
    "node_modules/@cacheable/memory": "workflow_dispatch",
    "node_modules/@cacheable/utils": "workflow_dispatch",
    "node_modules/@playwright/test": "release",
    "node_modules/baseline-browser-mapping": "workflow_dispatch",
    "node_modules/cacheable": "workflow_dispatch",
    "node_modules/caniuse-lite": "workflow_run",
    "node_modules/file-entry-cache": "workflow_dispatch",
    "node_modules/flat-cache": "workflow_dispatch",
    "node_modules/node-releases": "schedule",
    "node_modules/playwright": "release",
    "node_modules/playwright-core": "release",
    "node_modules/tinyglobby": "release",
    "node_modules/zod": "workflow_dispatch",
}


class NpmProvenanceError(ValueError):
    """npm output, lock data or reviewed publisher identity is inconsistent."""


@dataclass(frozen=True)
class ReviewedAttestation:
    location: str
    name: str
    version: str
    sha512: str
    repository: str
    workflow: str
    ref: str
    repository_id: str
    owner_id: str
    source_commit: str

    def render(self) -> str:
        return "\t".join((
            self.location,
            self.name,
            self.version,
            self.sha512,
            self.repository,
            self.workflow,
            self.ref,
            self.repository_id,
            self.owner_id,
            self.source_commit,
        ))


def _safe_identity(entry: ReviewedAttestation) -> bool:
    return (
        entry.location.startswith("node_modules/")
        and ".." not in entry.location.split("/")
        and bool(entry.name)
        and bool(entry.version)
        and HEX512.fullmatch(entry.sha512) is not None
        and REPOSITORY.fullmatch(entry.repository) is not None
        and WORKFLOW.fullmatch(entry.workflow) is not None
        and REF.fullmatch(entry.ref) is not None
        and ".." not in entry.ref
        and "@{" not in entry.ref
        and IDENTIFIER.fullmatch(entry.repository_id) is not None
        and IDENTIFIER.fullmatch(entry.owner_id) is not None
        and COMMIT.fullmatch(entry.source_commit) is not None
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NpmProvenanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _bounded_regular(path: Path, maximum: int, label: str) -> bytes:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or not 1 <= info.st_size <= maximum
    ):
        raise NpmProvenanceError(f"{label} is linked, special, empty or oversized")
    return path.read_bytes()


def parse_policy(path: Path) -> list[ReviewedAttestation]:
    try:
        text = _bounded_regular(path, MAX_POLICY_BYTES, "npm provenance policy").decode("utf-8")
    except UnicodeError as exc:
        raise NpmProvenanceError("npm provenance policy is not UTF-8") from exc
    entries: list[ReviewedAttestation] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 10:
            raise NpmProvenanceError(f"invalid policy entry at line {number}")
        entry = ReviewedAttestation(*fields)
        if entry.location in seen:
            raise NpmProvenanceError(f"duplicate policy location at line {number}")
        if not _safe_identity(entry):
            raise NpmProvenanceError(f"unsafe policy entry at line {number}")
        seen.add(entry.location)
        entries.append(entry)
    if not entries or entries != sorted(entries, key=lambda entry: entry.location):
        raise NpmProvenanceError("npm provenance policy is empty or not canonically sorted")
    return entries


def read_report(stream) -> dict[str, object]:
    raw = stream.read(MAX_REPORT_BYTES + 1)
    if not raw or len(raw) > MAX_REPORT_BYTES:
        raise NpmProvenanceError("npm provenance report is empty or oversized")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise NpmProvenanceError("npm provenance report is not valid UTF-8 JSON") from exc
    if not isinstance(report, dict):
        raise NpmProvenanceError("npm provenance report root is not an object")
    return report


def _payload(bundle: object) -> dict[str, object]:
    if not isinstance(bundle, dict):
        raise NpmProvenanceError("npm attestation bundle is not an object")
    envelope = bundle.get("bundle", {}).get("dsseEnvelope") if isinstance(bundle.get("bundle"), dict) else None
    encoded = envelope.get("payload") if isinstance(envelope, dict) else None
    if not isinstance(encoded, str) or len(encoded) > 8 * 1024 * 1024:
        raise NpmProvenanceError("npm attestation payload is missing or oversized")
    try:
        raw = base64.b64decode(encoded, validate=True)
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
        raise NpmProvenanceError("npm attestation payload is malformed") from exc
    if not isinstance(payload, dict):
        raise NpmProvenanceError("npm attestation payload is not an object")
    return payload


def _subject(payload: dict[str, object], package: LockedPackage) -> None:
    subject = payload.get("subject")
    if (
        not isinstance(subject, list)
        or len(subject) != 1
        or not isinstance(subject[0], dict)
        or subject[0].get("name") != package.purl
        or subject[0].get("digest") != {"sha512": package.digest}
    ):
        raise NpmProvenanceError(f"attestation subject does not match lock: {package.path}")


def _identity(
    package: LockedPackage,
    repository: object,
    workflow: object,
    ref: object,
    repository_id: object,
    owner_id: object,
    source_commit: object,
) -> ReviewedAttestation:
    entry = ReviewedAttestation(
        package.path,
        package.name,
        package.version,
        package.digest,
        repository,
        workflow,
        ref,
        repository_id,
        owner_id,
        source_commit,
    )
    if not _safe_identity(entry):
        raise NpmProvenanceError(f"npm provenance identity is malformed: {package.path}")
    return entry


def _slsa_v1_identity(
    slsa: dict[str, object], package: LockedPackage
) -> ReviewedAttestation:
    if (
        slsa.get("_type") != "https://in-toto.io/Statement/v1"
        or slsa.get("predicateType") != SLSA_V1_PREDICATE
    ):
        raise NpmProvenanceError(f"npm SLSA v1 statement type changed: {package.path}")
    predicate = slsa.get("predicate")
    build = predicate.get("buildDefinition") if isinstance(predicate, dict) else None
    run = predicate.get("runDetails") if isinstance(predicate, dict) else None
    external = build.get("externalParameters") if isinstance(build, dict) else None
    workflow = external.get("workflow") if isinstance(external, dict) else None
    internal = build.get("internalParameters") if isinstance(build, dict) else None
    github = internal.get("github") if isinstance(internal, dict) else None
    resolved = build.get("resolvedDependencies") if isinstance(build, dict) else None
    builder = run.get("builder") if isinstance(run, dict) else None
    metadata = run.get("metadata") if isinstance(run, dict) else None
    if (
        not isinstance(build, dict)
        or build.get("buildType") != SLSA_V1_BUILD_TYPE
        or not isinstance(workflow, dict)
        or not isinstance(github, dict)
        or github.get("event_name")
        != NON_PUSH_EVENT_BY_LOCATION.get(package.path, "push")
        or not isinstance(resolved, list)
        or len(resolved) != 1
        or not isinstance(resolved[0], dict)
        or builder != {"id": SLSA_V1_BUILDER}
        or not isinstance(metadata, dict)
    ):
        raise NpmProvenanceError(f"npm SLSA v1 build shape changed: {package.path}")
    repository = workflow.get("repository")
    workflow_path = workflow.get("path")
    ref = workflow.get("ref")
    repository_id = github.get("repository_id")
    owner_id = github.get("repository_owner_id")
    source_digest = resolved[0].get("digest")
    source_commit = source_digest.get("gitCommit") if isinstance(source_digest, dict) else None
    if resolved[0].get("uri") != f"git+{repository}@{ref}":
        raise NpmProvenanceError(f"npm SLSA v1 source URI changed: {package.path}")
    invocation = metadata.get("invocationId")
    if not isinstance(invocation, str) or not invocation.startswith(f"{repository}/actions/runs/"):
        raise NpmProvenanceError(f"npm SLSA v1 invocation identity changed: {package.path}")
    return _identity(
        package,
        repository,
        workflow_path,
        ref,
        repository_id,
        owner_id,
        source_commit,
    )


def _slsa_v02_identity(
    slsa: dict[str, object], package: LockedPackage
) -> ReviewedAttestation:
    if (
        slsa.get("_type") != "https://in-toto.io/Statement/v0.1"
        or slsa.get("predicateType") != SLSA_V02_PREDICATE
    ):
        raise NpmProvenanceError(f"npm SLSA v0.2 statement type changed: {package.path}")
    predicate = slsa.get("predicate")
    invocation = predicate.get("invocation") if isinstance(predicate, dict) else None
    config = invocation.get("configSource") if isinstance(invocation, dict) else None
    environment = invocation.get("environment") if isinstance(invocation, dict) else None
    metadata = predicate.get("metadata") if isinstance(predicate, dict) else None
    materials = predicate.get("materials") if isinstance(predicate, dict) else None
    expected_environment = {
        "GITHUB_EVENT_NAME",
        "GITHUB_REF",
        "GITHUB_REPOSITORY",
        "GITHUB_REPOSITORY_ID",
        "GITHUB_REPOSITORY_OWNER_ID",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_ID",
        "GITHUB_SHA",
        "GITHUB_WORKFLOW_REF",
        "GITHUB_WORKFLOW_SHA",
    }
    if (
        not isinstance(predicate, dict)
        or predicate.get("buildType") != SLSA_V02_BUILD_TYPE
        or predicate.get("builder") != {"id": SLSA_V02_BUILDER}
        or not isinstance(invocation, dict)
        or invocation.get("parameters") != {}
        or not isinstance(config, dict)
        or not isinstance(environment, dict)
        or set(environment) != expected_environment
        or not isinstance(metadata, dict)
        or metadata.get("completeness") != {
            "parameters": False,
            "environment": False,
            "materials": False,
        }
        or metadata.get("reproducible") is not False
        or not isinstance(materials, list)
        or len(materials) != 1
        or not isinstance(materials[0], dict)
    ):
        raise NpmProvenanceError(f"npm SLSA v0.2 build shape changed: {package.path}")
    repository_slug = environment.get("GITHUB_REPOSITORY")
    repository = f"https://github.com/{repository_slug}" if isinstance(repository_slug, str) else None
    workflow = config.get("entryPoint")
    ref = environment.get("GITHUB_REF")
    repository_id = environment.get("GITHUB_REPOSITORY_ID")
    owner_id = environment.get("GITHUB_REPOSITORY_OWNER_ID")
    source_commit = environment.get("GITHUB_SHA")
    source_digest = {"sha1": source_commit}
    source_uri = f"git+{repository}@{ref}"
    run_id = environment.get("GITHUB_RUN_ID")
    run_attempt = environment.get("GITHUB_RUN_ATTEMPT")
    if (
        environment.get("GITHUB_EVENT_NAME") != "push"
        or not isinstance(run_id, str)
        or IDENTIFIER.fullmatch(run_id) is None
        or not isinstance(run_attempt, str)
        or IDENTIFIER.fullmatch(run_attempt) is None
        or environment.get("GITHUB_WORKFLOW_REF") != f"{repository_slug}/{workflow}@{ref}"
        or environment.get("GITHUB_WORKFLOW_SHA") != source_commit
        or config.get("uri") != source_uri
        or config.get("digest") != source_digest
        or materials[0] != {"uri": source_uri, "digest": source_digest}
        or metadata.get("buildInvocationId") != f"{run_id}-{run_attempt}"
    ):
        raise NpmProvenanceError(f"npm SLSA v0.2 source identity changed: {package.path}")
    return _identity(
        package,
        repository,
        workflow,
        ref,
        repository_id,
        owner_id,
        source_commit,
    )


def _reviewed_entry(item: object, locked: dict[str, LockedPackage]) -> ReviewedAttestation:
    if not isinstance(item, dict):
        raise NpmProvenanceError("verified npm entry is not an object")
    location = item.get("location")
    if not isinstance(location, str) or location not in locked:
        raise NpmProvenanceError("verified npm entry is absent from the lock")
    package = locked[location]
    if item.get("name") != package.name or item.get("version") != package.version:
        raise NpmProvenanceError(f"verified package identity does not match lock: {location}")
    if item.get("registry") != f"{REGISTRY}/":
        raise NpmProvenanceError(f"verified package registry changed: {location}")
    attestations = item.get("attestations")
    provenance_predicate = LEGACY_PROVENANCE_BY_LOCATION.get(location, SLSA_V1_PREDICATE)
    if not isinstance(attestations, dict) or attestations.get("provenance") != {
        "predicateType": provenance_predicate,
    }:
        raise NpmProvenanceError(f"npm provenance summary changed: {location}")
    attestation_url = attestations.get("url")
    if not isinstance(attestation_url, str):
        raise NpmProvenanceError(f"npm attestation URL is missing: {location}")
    parsed_url = urlsplit(attestation_url)
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "registry.npmjs.org"
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.port is not None
        or not parsed_url.path.startswith("/-/npm/v1/attestations/")
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise NpmProvenanceError(f"npm attestation URL is unsafe: {location}")

    bundles = item.get("attestationBundles")
    if not isinstance(bundles, list) or len(bundles) != 2:
        raise NpmProvenanceError(f"npm attestation bundle set changed: {location}")
    by_predicate: dict[str, dict[str, object]] = {}
    for bundle in bundles:
        if not isinstance(bundle, dict) or not isinstance(bundle.get("predicateType"), str):
            raise NpmProvenanceError(f"npm attestation predicate is malformed: {location}")
        predicate_type = bundle["predicateType"]
        if predicate_type in by_predicate:
            raise NpmProvenanceError(f"duplicate npm attestation predicate: {location}")
        by_predicate[predicate_type] = _payload(bundle)
    if set(by_predicate) != {PUBLISH_PREDICATE, provenance_predicate}:
        raise NpmProvenanceError(f"npm attestation predicates changed: {location}")

    publish = by_predicate[PUBLISH_PREDICATE]
    _subject(publish, package)
    if (
        publish.get("_type") != "https://in-toto.io/Statement/v0.1"
        or publish.get("predicateType") != PUBLISH_PREDICATE
        or publish.get("predicate") != {
            "name": package.name,
            "version": package.version,
            "registry": REGISTRY,
        }
    ):
        raise NpmProvenanceError(f"npm publish predicate changed: {location}")

    slsa = by_predicate[provenance_predicate]
    _subject(slsa, package)
    if provenance_predicate == SLSA_V02_PREDICATE:
        return _slsa_v02_identity(slsa, package)
    return _slsa_v1_identity(slsa, package)


def verify(report: dict[str, object], lock_path: Path, policy_path: Path) -> tuple[int, int]:
    if set(report) != {"invalid", "missing", "verified"}:
        raise NpmProvenanceError("npm provenance report schema changed")
    if report["invalid"] != [] or report["missing"] != []:
        raise NpmProvenanceError("npm reported invalid or missing attestations")
    verified = report["verified"]
    if not isinstance(verified, list) or not verified:
        raise NpmProvenanceError("npm reported no verified provenance")
    packages, _ = parse_lock(lock_path)
    locked = {package.path: package for package in packages}
    observed: list[ReviewedAttestation] = []
    seen: set[str] = set()
    for item in verified:
        entry = _reviewed_entry(item, locked)
        if entry.location in seen:
            raise NpmProvenanceError(f"duplicate verified npm location: {entry.location}")
        seen.add(entry.location)
        observed.append(entry)
    observed.sort(key=lambda entry: entry.location)
    policy = parse_policy(policy_path)
    policy_locations = {entry.location for entry in policy}
    configured_exceptions = (
        set(LEGACY_PROVENANCE_BY_LOCATION) | set(NON_PUSH_EVENT_BY_LOCATION)
    )
    if not (configured_exceptions & set(locked)) <= policy_locations:
        raise NpmProvenanceError("npm provenance exception is absent from policy")
    if observed != policy:
        observed_by_location = {entry.location: entry for entry in observed}
        policy_by_location = {entry.location: entry for entry in policy}
        missing = sorted(set(policy_by_location) - set(observed_by_location))
        extra = sorted(set(observed_by_location) - set(policy_by_location))
        changed = sorted(
            location for location in set(observed_by_location) & set(policy_by_location)
            if observed_by_location[location] != policy_by_location[location]
        )
        raise NpmProvenanceError(
            f"npm provenance policy mismatch: missing={missing}, extra={extra}, changed={changed}"
        )
    return len(observed), len(packages) - len(observed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    try:
        report = read_report(sys.stdin.buffer)
        attested, outside = verify(report, args.lockfile, args.policy)
        print(
            f"verified {attested} reviewed npm attestations; "
            f"{outside} lock entries outside the attested CI baseline"
        )
        return 0
    except (OSError, NpmProvenanceError, ValueError) as exc:
        print(f"npm provenance verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
