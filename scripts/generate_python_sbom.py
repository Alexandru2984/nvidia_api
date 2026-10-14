#!/usr/bin/env python3
"""Generate and verify a deterministic CycloneDX SBOM from the wheel lockfile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
SPEC_VERSION = "1.7"
LOCK_LINE = re.compile(
    r"(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s]+) "
    r"--hash=sha256:(?P<digest>[0-9a-f]{64})"
)
COMMIT = re.compile(r"[0-9a-f]{40}")


class SbomError(ValueError):
    """The lockfile or SBOM does not satisfy the production contract."""


@dataclass(frozen=True)
class LockedWheel:
    name: str
    canonical_name: str
    version: str
    digest: str

    @property
    def purl(self) -> str:
        return f"pkg:pypi/{quote(self.canonical_name, safe='-')}@{quote(self.version, safe='.-_')}"


def canonicalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(lock_path: Path) -> list[LockedWheel]:
    wheels: list[LockedWheel] = []
    seen: set[str] = set()
    for number, raw in enumerate(lock_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_LINE.fullmatch(line)
        if match is None:
            raise SbomError(f"unsupported lock entry at line {number}")
        canonical = canonicalize_name(match.group("name"))
        if canonical in seen:
            raise SbomError(f"duplicate package at line {number}: {canonical}")
        seen.add(canonical)
        wheels.append(LockedWheel(
            match.group("name"),
            canonical,
            match.group("version"),
            match.group("digest"),
        ))
    if not wheels:
        raise SbomError("lockfile has no runtime packages")
    return sorted(wheels, key=lambda wheel: wheel.canonical_name)


def build_sbom(lock_path: Path, commit: str) -> dict[str, object]:
    if COMMIT.fullmatch(commit) is None:
        raise SbomError("commit must be a full lowercase SHA-1")
    lock_bytes = lock_path.read_bytes()
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    wheels = parse_lock(lock_path)
    root_ref = f"aichat-python-runtime:{commit}"
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://aichat.micutu.com/runtime/{commit}/{lock_digest}",
    )
    components = [
        {
            "type": "library",
            "bom-ref": wheel.purl,
            "name": wheel.name,
            "version": wheel.version,
            "hashes": [{"alg": "SHA-256", "content": wheel.digest}],
            "purl": wheel.purl,
            "properties": [
                {"name": "aichat:artifact-kind", "value": "selected-binary-wheel"},
            ],
        }
        for wheel in wheels
    ]
    return {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": "aichat-python-runtime",
                "version": commit,
            },
            "properties": [
                {"name": "aichat:requirements-commit", "value": commit},
                {"name": "aichat:requirements-lock-sha256", "value": lock_digest},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [wheel.purl for wheel in wheels]},
            *({"ref": wheel.purl, "dependsOn": []} for wheel in wheels),
        ],
    }


def validate_sbom(document: object, lock_path: Path, commit: str) -> None:
    expected = build_sbom(lock_path, commit)
    if document != expected:
        raise SbomError("SBOM does not exactly match the committed wheel lock")


def render_sbom(document: dict[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    temporary.chmod(0o644)
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lockfile", type=Path)
    parser.add_argument("--commit", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--check", type=Path)
    args = parser.parse_args()

    try:
        expected = build_sbom(args.lockfile, args.commit)
        if args.check is not None:
            document = json.loads(args.check.read_text(encoding="utf-8"))
            validate_sbom(document, args.lockfile, args.commit)
            print(f"validated {len(expected['components'])} CycloneDX components")
        else:
            write_atomic(args.output, render_sbom(expected))
            print(f"generated {len(expected['components'])} CycloneDX components")
        return 0
    except (OSError, SbomError, json.JSONDecodeError) as exc:
        print(f"SBOM validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
