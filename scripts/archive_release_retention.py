#!/usr/bin/env python3
"""Bound executable release roots while preserving private verified archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


RELEASE_RE = re.compile(r"^release-\d{8}T\d{6}_\d+$")
LEGACY_RE = re.compile(r"^legacy-\d{8}T\d{6}_\d+$")
DEFAULT_KEEP_INACTIVE = 2


@dataclass(frozen=True)
class ReleaseFamily:
    name: str
    release_root: Path
    live_path: Path
    archive_root: Path
    max_files: int
    max_bytes: int


ARCHIVE_ROOT = Path("/home/micu/backups/nvidia_release_archive")
FAMILIES = {
    "backend": ReleaseFamily(
        "backend",
        Path("/opt/aichat-backend-releases"),
        Path("/opt/aichat-backend-current"),
        ARCHIVE_ROOT / "backend",
        5_000,
        128 * 1024 * 1024,
    ),
    "python": ReleaseFamily(
        "python",
        Path("/opt/aichat-python-envs"),
        Path("/opt/aichat-python-current"),
        ARCHIVE_ROOT / "python",
        20_000,
        512 * 1024 * 1024,
    ),
    "frontend": ReleaseFamily(
        "frontend",
        Path("/var/www/aichat-releases"),
        Path("/var/www/aichat.micutu.com"),
        ARCHIVE_ROOT / "frontend",
        5_000,
        256 * 1024 * 1024,
    ),
}


class RetentionError(RuntimeError):
    """The release layout is unsafe or inconsistent."""


def _lstat_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise RetentionError(f"cannot inspect {path}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise RetentionError(f"not a real directory: {path}")
    return info


def validate_tree(
    path: Path,
    family: ReleaseFamily,
    *,
    expected_uid: int,
    expected_gid: int,
    permit_legacy_ownership: bool = False,
) -> tuple[int, int]:
    files = 0
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(path, followlinks=False):
        directory_path = Path(directory)
        info = directory_path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise RetentionError(f"non-directory in release walk: {directory_path}")
        if not permit_legacy_ownership and (
            info.st_uid != expected_uid
            or info.st_gid != expected_gid
            or stat.S_IMODE(info.st_mode) != 0o755
        ):
            raise RetentionError(f"unsafe directory ownership or mode: {directory_path}")

        for name in dirnames + filenames:
            candidate = directory_path / name
            candidate_info = candidate.lstat()
            if stat.S_ISLNK(candidate_info.st_mode):
                raise RetentionError(f"release tree contains a symlink: {candidate}")
            if stat.S_ISDIR(candidate_info.st_mode):
                continue
            if not stat.S_ISREG(candidate_info.st_mode):
                raise RetentionError(f"release tree contains a special file: {candidate}")
            if not permit_legacy_ownership and (
                candidate_info.st_uid != expected_uid
                or candidate_info.st_gid != expected_gid
                or stat.S_IMODE(candidate_info.st_mode) not in {0o644, 0o755}
            ):
                raise RetentionError(f"unsafe file ownership or mode: {candidate}")
            files += 1
            total_bytes += candidate_info.st_size
            if files > family.max_files or total_bytes > family.max_bytes:
                raise RetentionError(f"release exceeds archive bounds: {path}")
    if files == 0:
        raise RetentionError(f"refusing to archive an empty release: {path}")
    return files, total_bytes


def plan_family(
    family: ReleaseFamily,
    keep_inactive: int = DEFAULT_KEEP_INACTIVE,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> dict[str, object]:
    if keep_inactive < 1:
        raise RetentionError("at least one inactive rollback must be retained")

    root_info = _lstat_directory(family.release_root)
    if (
        root_info.st_uid != expected_uid
        or root_info.st_gid != expected_gid
        or stat.S_IMODE(root_info.st_mode) != 0o755
    ):
        raise RetentionError(f"unsafe release-root ownership or mode: {family.release_root}")

    try:
        live_info = family.live_path.lstat()
    except OSError as exc:
        raise RetentionError(f"cannot inspect live path {family.live_path}: {exc}") from exc
    if (
        not stat.S_ISLNK(live_info.st_mode)
        or live_info.st_uid != expected_uid
        or live_info.st_gid != expected_gid
    ):
        raise RetentionError(f"live path is not the trusted symlink: {family.live_path}")
    active = family.live_path.resolve(strict=True)
    trusted_root = family.release_root.resolve(strict=True)
    if active.parent != trusted_root or not RELEASE_RE.fullmatch(active.name):
        raise RetentionError(f"live target leaves the trusted release root: {active}")

    releases: list[Path] = []
    legacy: list[Path] = []
    for entry in family.release_root.iterdir():
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RetentionError(f"unexpected release-root entry: {entry}")
        if RELEASE_RE.fullmatch(entry.name):
            releases.append(entry)
        elif LEGACY_RE.fullmatch(entry.name):
            legacy.append(entry)
        else:
            raise RetentionError(f"unexpected release-root entry: {entry}")

    if active not in releases:
        raise RetentionError("the active release is missing from the release inventory")
    inactive = sorted((path for path in releases if path != active), reverse=True)
    retained = [active, *inactive[:keep_inactive]]
    candidates = [*sorted(inactive[keep_inactive:]), *sorted(legacy)]
    for candidate in candidates:
        validate_tree(
            candidate,
            family,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            permit_legacy_ownership=bool(LEGACY_RE.fullmatch(candidate.name)),
        )

    return {
        "active": active,
        "retained": retained,
        "candidates": candidates,
    }


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_archive(path: Path, prefix: str, family: ReleaseFamily) -> None:
    files = 0
    total_bytes = 0
    with tarfile.open(path, mode="r:gz") as archive:
        members = archive.getmembers()
        if not members:
            raise RetentionError(f"archive is empty: {path}")
        for member in members:
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise RetentionError(f"archive contains an unsafe path: {member.name}")
            if member.name != prefix and not member.name.startswith(f"{prefix}/"):
                raise RetentionError(f"archive member leaves its prefix: {member.name}")
            if not (member.isdir() or member.isreg()):
                raise RetentionError(f"archive contains a link or special entry: {member.name}")
            if member.isreg():
                files += 1
                total_bytes += member.size
                if files > family.max_files or total_bytes > family.max_bytes:
                    raise RetentionError(f"archive exceeds family bounds: {path}")
    if files == 0:
        raise RetentionError(f"archive contains no files: {path}")


def _make_private_directory(path: Path, uid: int, gid: int) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        if cursor.is_symlink():
            raise RetentionError(f"unsafe archive directory: {cursor}")
        missing.append(cursor)
        cursor = cursor.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700)
        os.chown(directory, uid, gid)
        directory.chmod(0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise RetentionError(f"unsafe archive directory: {path}")
    os.chown(path, uid, gid)
    path.chmod(0o700)


def _freeze_tree(path: Path, uid: int, gid: int) -> None:
    """Remove service-user mutability before reading a retired legacy tree."""
    for directory, dirnames, filenames in os.walk(path, followlinks=False):
        directory_path = Path(directory)
        os.chown(directory_path, uid, gid)
        directory_path.chmod(0o755)
        for name in dirnames:
            child = directory_path / name
            os.chown(child, uid, gid)
            child.chmod(0o755)
        for name in filenames:
            child = directory_path / name
            info = child.lstat()
            os.chown(child, uid, gid)
            child.chmod(0o755 if stat.S_IMODE(info.st_mode) & 0o111 else 0o644)


def _fsync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def archive_candidate(
    family: ReleaseFamily,
    candidate: Path,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> Path:
    if candidate.parent.resolve(strict=True) != family.release_root.resolve(strict=True):
        raise RetentionError(f"candidate leaves trusted root: {candidate}")
    if not (RELEASE_RE.fullmatch(candidate.name) or LEGACY_RE.fullmatch(candidate.name)):
        raise RetentionError(f"unsafe candidate name: {candidate.name}")
    _lstat_directory(candidate)
    validate_tree(
        candidate,
        family,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        permit_legacy_ownership=bool(LEGACY_RE.fullmatch(candidate.name)),
    )

    _make_private_directory(family.archive_root, expected_uid, expected_gid)
    archive_path = family.archive_root / f"{family.name}--{candidate.name}.tar.gz"
    digest_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    if archive_path.exists() or archive_path.is_symlink() or digest_path.exists() or digest_path.is_symlink():
        raise RetentionError(f"archive destination already exists: {archive_path}")

    retiring = family.release_root / f".retiring-{candidate.name}"
    if retiring.exists() or retiring.is_symlink():
        raise RetentionError(f"retirement staging path already exists: {retiring}")
    candidate.rename(retiring)
    temporary: Path | None = None
    try:
        _freeze_tree(retiring, expected_uid, expected_gid)
        validate_tree(
            retiring,
            family,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        with tempfile.NamedTemporaryFile(
            dir=family.archive_root,
            prefix=f".{candidate.name}.",
            suffix=".tar.gz",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
        prefix = f"{family.name}/{candidate.name}"
        with tarfile.open(temporary, mode="w:gz", compresslevel=6) as archive:
            archive.add(retiring, arcname=prefix, recursive=True)
        temporary.chmod(0o600)
        os.chown(temporary, expected_uid, expected_gid)
        _verify_archive(temporary, prefix, family)
        digest = _hash_file(temporary)
        temporary.replace(archive_path)
        digest_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii")
        digest_path.chmod(0o600)
        os.chown(digest_path, expected_uid, expected_gid)
        if _hash_file(archive_path) != digest:
            raise RetentionError(f"archive digest verification failed: {archive_path}")
        _fsync_file(archive_path)
        _fsync_file(digest_path)
        archive_directory = os.open(family.archive_root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(archive_directory)
        finally:
            os.close(archive_directory)
        shutil.rmtree(retiring)
        return archive_path
    except Exception:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        if retiring.exists() and not candidate.exists():
            retiring.rename(candidate)
        raise


def serializable_plan(plan: dict[str, object]) -> dict[str, object]:
    return {
        "active": str(plan["active"]),
        "retained": [str(path) for path in plan["retained"]],
        "archive_candidates": [str(path) for path in plan["candidates"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="archive candidates and remove source trees")
    parser.add_argument("--family", choices=["all", *FAMILIES], default="all")
    parser.add_argument("--keep-inactive", type=int, default=DEFAULT_KEEP_INACTIVE)
    args = parser.parse_args()

    if args.apply and os.geteuid() != 0:
        parser.error("--apply requires root")
    selected = FAMILIES.values() if args.family == "all" else [FAMILIES[args.family]]
    try:
        plans = {
            family.name: plan_family(family, args.keep_inactive)
            for family in selected
        }
        if not args.apply:
            print(json.dumps(
                {name: serializable_plan(plan) for name, plan in plans.items()},
                indent=2,
                sort_keys=True,
            ))
            return 0
        for family in selected:
            for candidate in plans[family.name]["candidates"]:
                archive = archive_candidate(family, candidate)
                print(f"archived {candidate} -> {archive}")
        return 0
    except (OSError, RetentionError, tarfile.TarError) as exc:
        print(f"release retention failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
