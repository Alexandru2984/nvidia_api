#!/usr/bin/env python3
"""Verify that backend CI uses the exact runtime wheels plus reviewed test tools."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from check_requirements_lock import LOCK_RE, REQUIREMENT_RE, canonicalize, parse_file, validate


EXPECTED_TEST_TRANSITIVES = frozenset({"iniconfig", "pluggy", "pygments"})
EXPECTED_AUDIT_PACKAGES = frozenset({
    "boolean-py",
    "cachecontrol",
    "certifi",
    "charset-normalizer",
    "cyclonedx-python-lib",
    "defusedxml",
    "filelock",
    "idna",
    "license-expression",
    "markdown-it-py",
    "mdurl",
    "msgpack",
    "packageurl-python",
    "packaging",
    "pip",
    "pip-api",
    "pip-audit",
    "pip-requirements-parser",
    "platformdirs",
    "py-serializable",
    "pygments",
    "pyparsing",
    "requests",
    "rich",
    "sortedcontainers",
    "tomli",
    "tomli-w",
    "urllib3",
})
EXPECTED_PIP_AUDIT_VERSION = "2.10.1"


class CiLockError(ValueError):
    """The CI lock is incomplete, divergent, or unexpectedly expanded."""


@dataclass(frozen=True)
class LockedArtifact:
    display_name: str
    version: str
    digest: str


def parse_lock(path: Path) -> dict[str, LockedArtifact]:
    parsed: dict[str, LockedArtifact] = {}
    order: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOCK_RE.fullmatch(line)
        if match is None:
            raise CiLockError(f"{path}:{number}: invalid CI lock entry")
        canonical = canonicalize(match.group(1))
        if canonical in parsed:
            raise CiLockError(f"{path}:{number}: duplicate CI lock package")
        parsed[canonical] = LockedArtifact(
            display_name=match.group(1),
            version=match.group(2),
            digest=match.group(3),
        )
        order.append(canonical)
    if not parsed:
        raise CiLockError(f"{path}: CI lock is empty")
    if order != sorted(order):
        raise CiLockError(f"{path}: CI lock is not canonically sorted")
    return parsed


def check(
    requirements_path: Path,
    development_path: Path,
    runtime_lock_path: Path,
    ci_lock_path: Path,
) -> tuple[int, int, int]:
    runtime_count = validate(requirements_path, runtime_lock_path)
    runtime = parse_lock(runtime_lock_path)
    ci = parse_lock(ci_lock_path)
    development = parse_file(development_path, REQUIREMENT_RE, "development requirement")

    if set(runtime) & set(development):
        raise CiLockError("development requirements duplicate runtime packages")
    expected = set(runtime) | set(development) | set(EXPECTED_TEST_TRANSITIVES)
    if set(ci) != expected:
        missing = sorted(expected - set(ci))
        extra = sorted(set(ci) - expected)
        raise CiLockError(f"CI lock package-set mismatch: missing={missing}, extra={extra}")

    for name, artifact in runtime.items():
        candidate = ci[name]
        if (candidate.version, candidate.digest) != (artifact.version, artifact.digest):
            raise CiLockError(f"CI lock diverges from production artifact: {name}")
    for name, (display_name, version) in development.items():
        candidate = ci[name]
        if (candidate.display_name, candidate.version) != (display_name, version):
            raise CiLockError(f"CI lock diverges from development requirement: {name}")
    return runtime_count, len(development), len(EXPECTED_TEST_TRANSITIVES)


def check_audit_lock(audit_lock_path: Path) -> int:
    audit = parse_lock(audit_lock_path)
    if set(audit) != set(EXPECTED_AUDIT_PACKAGES):
        missing = sorted(EXPECTED_AUDIT_PACKAGES - set(audit))
        extra = sorted(set(audit) - EXPECTED_AUDIT_PACKAGES)
        raise CiLockError(
            f"audit lock package-set mismatch: missing={missing}, extra={extra}"
        )
    if audit["pip-audit"].version != EXPECTED_PIP_AUDIT_VERSION:
        raise CiLockError("audit lock contains an unreviewed pip-audit version")
    return len(audit)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("requirements", type=Path)
    parser.add_argument("development", type=Path)
    parser.add_argument("runtime_lock", type=Path)
    parser.add_argument("ci_lock", type=Path)
    parser.add_argument("audit_lock", type=Path)
    args = parser.parse_args()
    try:
        runtime, direct, transitive = check(
            args.requirements, args.development, args.runtime_lock, args.ci_lock,
        )
        audit = check_audit_lock(args.audit_lock)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    print(
        f"validated CI lock: {runtime} runtime, {direct} direct test, "
        f"{transitive} transitive test packages; {audit} audit-tool packages"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
