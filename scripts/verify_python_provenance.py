#!/usr/bin/env python3
"""Cryptographically verify the reviewed PyPI provenance baseline."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit


LOCK_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s]+) "
    r"--hash=sha256:(?P<digest>[0-9a-f]{64})$"
)
MAX_LOCAL_BYTES = 256 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_PROVENANCE_BYTES = 4 * 1024 * 1024
MAX_WHEEL_BYTES = 64 * 1024 * 1024
PYPI_HOST = "pypi.org"
FILES_HOST = "files.pythonhosted.org"
PUBLISH_PREDICATE = "https://docs.pypi.org/attestations/publish/v1"
EXPECTED_LIBRARY_VERSION = "0.0.31"


class ProvenanceError(ValueError):
    """The lock, policy, index response, or attestation is unsafe."""


@dataclass(frozen=True)
class LockedWheel:
    name: str
    canonical_name: str
    version: str
    digest: str


def canonicalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ProvenanceError("provenance policy contains a duplicate JSON key")
        document[key] = value
    return document


def read_local(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file():
            raise ProvenanceError("local provenance input has an unsafe type")
        size = path.stat().st_size
        if not 1 <= size <= MAX_LOCAL_BYTES:
            raise ProvenanceError("local provenance input has an unsafe size")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProvenanceError("local provenance input is unavailable") from exc


def parse_lock(path: Path) -> list[LockedWheel]:
    wheels: list[LockedWheel] = []
    seen: set[str] = set()
    for number, raw in enumerate(read_local(path).splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_RE.fullmatch(line)
        if match is None:
            raise ProvenanceError(f"unsupported wheel lock entry at line {number}")
        canonical = canonicalize(match.group("name"))
        if canonical in seen:
            raise ProvenanceError(f"duplicate wheel lock entry at line {number}")
        seen.add(canonical)
        wheels.append(LockedWheel(
            name=match.group("name"),
            canonical_name=canonical,
            version=match.group("version"),
            digest=match.group("digest"),
        ))
    if not wheels:
        raise ProvenanceError("wheel lock is empty")
    return sorted(wheels, key=lambda wheel: wheel.canonical_name)


def parse_policy(
    path: Path,
    wheels: list[LockedWheel],
) -> dict[str, dict[str, Any] | None]:
    try:
        document = json.loads(read_local(path), object_pairs_hook=reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ProvenanceError("provenance policy is not valid JSON") from exc
    if not isinstance(document, dict) or set(document) != {"packages", "version"}:
        raise ProvenanceError("provenance policy has an unsupported shape")
    if document["version"] != 1 or not isinstance(document["packages"], dict):
        raise ProvenanceError("provenance policy version or package map is invalid")

    packages: dict[str, dict[str, Any] | None] = {}
    for raw_name, publisher in document["packages"].items():
        if not isinstance(raw_name, str) or canonicalize(raw_name) != raw_name:
            raise ProvenanceError("provenance policy package name is not canonical")
        if raw_name in packages:
            raise ProvenanceError("provenance policy contains a duplicate package")
        if publisher is not None:
            if not isinstance(publisher, dict) or set(publisher) != {
                "environment", "kind", "repository", "workflow",
            }:
                raise ProvenanceError(
                    "provenance publisher policy has an unsupported shape"
                )
            if publisher["kind"] != "GitHub":
                raise ProvenanceError("provenance publisher kind is unsupported")
            for field in ("repository", "workflow"):
                if not isinstance(publisher[field], str) or not publisher[field]:
                    raise ProvenanceError("provenance publisher policy is invalid")
            if re.fullmatch(
                r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                publisher["repository"],
            ) is None:
                raise ProvenanceError("provenance publisher repository is invalid")
            if re.fullmatch(r"[A-Za-z0-9_.-]+", publisher["workflow"]) is None:
                raise ProvenanceError("provenance publisher workflow is invalid")
            if publisher["environment"] is not None and (
                not isinstance(publisher["environment"], str)
                or re.fullmatch(r"[A-Za-z0-9_.-]+", publisher["environment"]) is None
            ):
                raise ProvenanceError("provenance publisher environment is invalid")
        packages[raw_name] = publisher

    locked = {wheel.canonical_name for wheel in wheels}
    if set(packages) != locked:
        raise ProvenanceError("provenance policy does not exactly cover the wheel lock")
    return packages


def validate_https_url(url: str, host: str) -> None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != host
        or parsed.port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ProvenanceError("package index returned an unsafe URL")


def bounded_get(
    session: Any,
    url: str,
    maximum: int,
    *,
    accept: str,
    statuses: frozenset[int] = frozenset({200}),
) -> tuple[int, bytes]:
    try:
        response = session.get(
            url,
            allow_redirects=False,
            headers={"Accept": accept},
            stream=True,
            timeout=(5, 30),
        )
    except Exception as exc:
        raise ProvenanceError("package index request failed") from exc
    try:
        if response.status_code not in statuses:
            raise ProvenanceError("package index returned an unexpected status")
        declared = response.headers.get("Content-Length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError as exc:
                raise ProvenanceError("package index returned an invalid size") from exc
            if not 0 <= declared_size <= maximum:
                raise ProvenanceError("package index response exceeds its size limit")
        content = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content) > maximum:
                raise ProvenanceError("package index response exceeds its size limit")
        return response.status_code, bytes(content)
    except ProvenanceError:
        raise
    except Exception as exc:
        raise ProvenanceError("package index response could not be read safely") from exc
    finally:
        response.close()


def select_artifact(metadata: object, wheel: LockedWheel) -> dict[str, Any]:
    if not isinstance(metadata, dict) or not isinstance(metadata.get("urls"), list):
        raise ProvenanceError("package metadata has an unsupported shape")
    candidates = []
    for item in metadata["urls"]:
        if not isinstance(item, dict) or not isinstance(item.get("digests"), dict):
            continue
        if item["digests"].get("sha256") == wheel.digest:
            candidates.append(item)
    if len(candidates) != 1:
        raise ProvenanceError("wheel hash does not identify exactly one PyPI artifact")
    artifact = candidates[0]
    filename = artifact.get("filename")
    url = artifact.get("url")
    if (
        artifact.get("packagetype") != "bdist_wheel"
        or artifact.get("yanked") is not False
        or not isinstance(filename, str)
        or not filename.endswith(".whl")
        or Path(filename).name != filename
        or not isinstance(url, str)
    ):
        raise ProvenanceError("selected PyPI artifact is unsafe or no longer usable")
    validate_https_url(url, FILES_HOST)
    return artifact


def load_attestation_api() -> dict[str, Any]:
    if (
        sys.version_info[:2] != (3, 14)
        or sys.platform != "linux"
        or platform.machine() != "x86_64"
    ):
        raise ProvenanceError("provenance verifier requires CPython 3.14 on Linux x86_64")
    try:
        import pypi_attestations
        from pypi_attestations import Distribution, GitHubPublisher, Provenance
    except ImportError as exc:
        raise ProvenanceError("hash-locked provenance verifier is unavailable") from exc
    if pypi_attestations.__version__ != EXPECTED_LIBRARY_VERSION:
        raise ProvenanceError("provenance verifier library version is unexpected")
    return {
        "Distribution": Distribution,
        "GitHubPublisher": GitHubPublisher,
        "Provenance": Provenance,
    }


def verify(lock_path: Path, policy_path: Path) -> tuple[int, int]:
    try:
        import requests
    except ImportError as exc:
        raise ProvenanceError("hash-locked HTTP verifier is unavailable") from exc
    api = load_attestation_api()
    wheels = parse_lock(lock_path)
    policies = parse_policy(policy_path, wheels)
    session = requests.Session()
    session.headers.update({"User-Agent": "AI-Chat-Hub-PyPI-provenance/1"})
    verified = 0
    unavailable = 0

    with tempfile.TemporaryDirectory(prefix="aichat-pypi-provenance-") as directory:
        root = Path(directory)
        for wheel in wheels:
            metadata_url = (
                f"https://{PYPI_HOST}/pypi/{quote(wheel.canonical_name, safe='')}/"
                f"{quote(wheel.version, safe='')}/json"
            )
            _, raw_metadata = bounded_get(
                session, metadata_url, MAX_METADATA_BYTES, accept="application/json",
            )
            try:
                metadata = json.loads(raw_metadata)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProvenanceError("package metadata is not valid JSON") from exc
            artifact = select_artifact(metadata, wheel)
            filename = artifact["filename"]
            provenance_url = (
                f"https://{PYPI_HOST}/integrity/{quote(wheel.canonical_name, safe='')}/"
                f"{quote(wheel.version, safe='')}/{quote(filename, safe='')}/provenance"
            )
            status, raw_provenance = bounded_get(
                session,
                provenance_url,
                MAX_PROVENANCE_BYTES,
                accept="application/vnd.pypi.integrity.v1+json",
                statuses=frozenset({200, 404}),
            )
            policy = policies[wheel.canonical_name]
            if policy is None:
                if status != 404:
                    raise ProvenanceError("unreviewed provenance appeared for a locked wheel")
                unavailable += 1
                print(f"No provenance published: {wheel.canonical_name}=={wheel.version}")
                continue
            if status != 200:
                raise ProvenanceError("reviewed wheel provenance is no longer available")

            try:
                provenance = api["Provenance"].model_validate_json(raw_provenance)
            except ValueError as exc:
                raise ProvenanceError("PyPI provenance object is malformed") from exc
            expected = api["GitHubPublisher"](**policy)
            if (
                len(provenance.attestation_bundles) != 1
                or provenance.attestation_bundles[0].publisher != expected
                or not provenance.attestation_bundles[0].attestations
            ):
                raise ProvenanceError("PyPI provenance publisher differs from reviewed policy")

            _, wheel_bytes = bounded_get(
                session,
                artifact["url"],
                MAX_WHEEL_BYTES,
                accept="application/octet-stream",
            )
            if hashlib.sha256(wheel_bytes).hexdigest() != wheel.digest:
                raise ProvenanceError("downloaded wheel differs from the committed hash lock")
            wheel_path = root / filename
            wheel_path.write_bytes(wheel_bytes)
            distribution = api["Distribution"].from_file(wheel_path)
            predicates: set[str] = set()
            for attestation in provenance.attestation_bundles[0].attestations:
                predicate, _ = attestation.verify(expected, distribution)
                predicate = str(predicate)
                if predicate in predicates:
                    raise ProvenanceError("PyPI provenance repeats an attestation predicate")
                predicates.add(predicate)
            if PUBLISH_PREDICATE not in predicates:
                raise ProvenanceError("reviewed PyPI publish attestation is missing")
            verified += 1
            print(f"Verified PyPI provenance: {wheel.canonical_name}=={wheel.version}")
    return verified, unavailable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    try:
        verified, unavailable = verify(args.lockfile, args.policy)
    except (OSError, ProvenanceError, ValueError) as exc:
        print(f"Python provenance verification failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"Verified {verified} locked wheel provenances; "
        f"{unavailable} reviewed wheels publish no provenance."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
