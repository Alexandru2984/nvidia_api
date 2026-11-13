#!/usr/bin/env python3
"""Generate and verify a deterministic CycloneDX SBOM from package-lock.json."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit


SCHEMA = "https://cyclonedx.org/schema/bom-1.7.schema.json"
SPEC_VERSION = "1.7"
COMMIT = re.compile(r"[0-9a-f]{40}")
TREE = re.compile(r"[0-9a-f]{40,64}")
VERSION = re.compile(r"[^\s\x00-\x1f\x7f]{1,200}")
INTEGRITY = re.compile(r"sha512-([A-Za-z0-9+/]{86}==)")
MAX_LOCK_BYTES = 16 * 1024 * 1024
MAX_COMPONENTS = 5_000
ALLOWED_LICENSES = frozenset({
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BlueOak-1.0.0",
    "CC-BY-4.0",
    "ISC",
    "MIT",
    "MPL-2.0",
})


class FrontendSbomError(ValueError):
    """The npm lock or SBOM does not satisfy the frontend release contract."""


@dataclass(frozen=True)
class LockedPackage:
    path: str
    name: str
    version: str
    digest: str
    license: str
    development: bool
    optional: bool
    peer: bool

    @property
    def purl(self) -> str:
        if self.name.startswith("@"):
            namespace, package = self.name.split("/", 1)
            identity = f"{quote(namespace, safe='')}/{quote(package, safe='.-_~')}"
        else:
            identity = quote(self.name, safe=".-_~")
        return f"pkg:npm/{identity}@{quote(self.version, safe='.-_~+')}"

    @property
    def bom_ref(self) -> str:
        return f"{self.purl}?package_path={quote(self.path, safe='.-_~')}"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise FrontendSbomError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_lock(path: Path) -> tuple[dict[str, object], bytes]:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or not 2 <= info.st_size <= MAX_LOCK_BYTES
    ):
        raise FrontendSbomError("package lock is linked, special, empty or oversized")
    content = path.read_bytes()
    try:
        text = content.decode("utf-8")
        document = json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise FrontendSbomError("package lock is not canonical UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise FrontendSbomError("package lock root must be an object")
    return document, content


def _package_name(path: str) -> str:
    parts = path.split("/")
    index = 0
    name = ""
    while index < len(parts):
        if parts[index] != "node_modules":
            raise FrontendSbomError(f"unsupported package path: {path}")
        index += 1
        if index >= len(parts):
            raise FrontendSbomError(f"unsupported package path: {path}")
        if parts[index].startswith("@"):
            if (
                index + 1 >= len(parts)
                or re.fullmatch(r"@[A-Za-z0-9._-]+", parts[index]) is None
                or re.fullmatch(r"[A-Za-z0-9._-]+", parts[index + 1]) is None
            ):
                raise FrontendSbomError(f"unsupported package path: {path}")
            name = f"{parts[index]}/{parts[index + 1]}"
            index += 2
        else:
            if re.fullmatch(r"[A-Za-z0-9._-]+", parts[index]) is None:
                raise FrontendSbomError(f"unsupported package path: {path}")
            name = parts[index]
            index += 1
    return name


def _sha512(integrity: object, path: str) -> str:
    if not isinstance(integrity, str) or (match := INTEGRITY.fullmatch(integrity)) is None:
        raise FrontendSbomError(f"package has no exact SHA-512 integrity: {path}")
    try:
        digest = base64.b64decode(match.group(1), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise FrontendSbomError(f"package integrity is invalid: {path}") from exc
    if len(digest) != 64:
        raise FrontendSbomError(f"package integrity length is invalid: {path}")
    return digest.hex()


def _validate_registry_url(value: object, path: str) -> None:
    if not isinstance(value, str) or len(value) > 2_048:
        raise FrontendSbomError(f"package registry URL is missing or oversized: {path}")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "registry.npmjs.org"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise FrontendSbomError(f"package registry URL leaves the reviewed host: {path}")


def parse_lock(lock_path: Path) -> tuple[list[LockedPackage], bytes]:
    document, lock_bytes = _load_lock(lock_path)
    if document.get("lockfileVersion") != 3:
        raise FrontendSbomError("package lock must use lockfileVersion 3")
    packages = document.get("packages")
    if not isinstance(packages, dict) or not 2 <= len(packages) <= MAX_COMPONENTS + 1:
        raise FrontendSbomError("package lock has an invalid package inventory")
    root = packages.get("")
    if not isinstance(root, dict) or root.get("name") != "frontend" or root.get("version") != "0.0.0":
        raise FrontendSbomError("package lock root identity is unexpected")

    parsed: list[LockedPackage] = []
    refs: set[str] = set()
    for path, metadata in packages.items():
        if path == "":
            continue
        if not isinstance(path, str) or not isinstance(metadata, dict):
            raise FrontendSbomError("package inventory contains an invalid entry")
        name = _package_name(path)
        declared_name = metadata.get("name")
        if declared_name is not None and declared_name != name:
            raise FrontendSbomError(f"package path/name mismatch: {path}")
        version = metadata.get("version")
        license_name = metadata.get("license")
        if not isinstance(version, str) or VERSION.fullmatch(version) is None:
            raise FrontendSbomError(f"package version is invalid: {path}")
        if license_name not in ALLOWED_LICENSES:
            raise FrontendSbomError(f"package license is missing or unreviewed: {path}")
        for field in ("dev", "optional", "peer"):
            if field in metadata and not isinstance(metadata[field], bool):
                raise FrontendSbomError(f"package {field} flag is not boolean: {path}")
        _validate_registry_url(metadata.get("resolved"), path)
        package = LockedPackage(
            path=path,
            name=name,
            version=version,
            digest=_sha512(metadata.get("integrity"), path),
            license=license_name,
            development=metadata.get("dev", False) is True,
            optional=metadata.get("optional", False) is True,
            peer=metadata.get("peer", False) is True,
        )
        if package.bom_ref in refs:
            raise FrontendSbomError(f"duplicate package reference: {path}")
        refs.add(package.bom_ref)
        parsed.append(package)
    return sorted(parsed, key=lambda package: package.path), lock_bytes


def build_sbom(lock_path: Path, commit: str, frontend_tree: str) -> dict[str, object]:
    if COMMIT.fullmatch(commit) is None:
        raise FrontendSbomError("commit must be a full lowercase SHA-1")
    if TREE.fullmatch(frontend_tree) is None:
        raise FrontendSbomError("frontend tree must be a full lowercase object ID")
    packages, lock_bytes = parse_lock(lock_path)
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    root_ref = f"aichat-frontend:{commit}:{frontend_tree}"
    serial = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"https://aichat.micutu.com/frontend/{commit}/{frontend_tree}/{lock_digest}",
    )
    components = [
        {
            "type": "library",
            "bom-ref": package.bom_ref,
            "name": package.name,
            "version": package.version,
            "hashes": [{"alg": "SHA-512", "content": package.digest}],
            "licenses": [{"expression": package.license}],
            "purl": package.purl,
            "properties": [
                {"name": "aichat:npm-package-path", "value": package.path},
                {"name": "aichat:development-only", "value": str(package.development).lower()},
                {"name": "aichat:optional", "value": str(package.optional).lower()},
                {"name": "aichat:peer", "value": str(package.peer).lower()},
            ],
        }
        for package in packages
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
                "name": "aichat-frontend",
                "version": commit,
            },
            "properties": [
                {"name": "aichat:source-commit", "value": commit},
                {"name": "aichat:frontend-tree", "value": frontend_tree},
                {"name": "aichat:package-lock-sha256", "value": lock_digest},
                {"name": "aichat:package-lock-version", "value": "3"},
            ],
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [package.bom_ref for package in packages]},
            *({"ref": package.bom_ref, "dependsOn": []} for package in packages),
        ],
    }


def render_sbom(document: dict[str, object]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def validate_sbom(document: object, lock_path: Path, commit: str, frontend_tree: str) -> None:
    if document != build_sbom(lock_path, commit, frontend_tree):
        raise FrontendSbomError("SBOM does not exactly match the committed npm lock")


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False,
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
    parser.add_argument("--frontend-tree", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--check", type=Path)
    args = parser.parse_args()
    try:
        expected = build_sbom(args.lockfile, args.commit, args.frontend_tree)
        if args.check is not None:
            document = json.loads(
                args.check.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
            )
            validate_sbom(document, args.lockfile, args.commit, args.frontend_tree)
            print(f"validated {len(expected['components'])} frontend CycloneDX components")
        else:
            write_atomic(args.output, render_sbom(expected))
            print(f"generated {len(expected['components'])} frontend CycloneDX components")
        return 0
    except (OSError, UnicodeError, FrontendSbomError, json.JSONDecodeError) as exc:
        print(f"frontend SBOM validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
