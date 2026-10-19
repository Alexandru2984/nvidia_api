#!/usr/bin/env python3
"""Create and verify root-authorized Ed25519 release attestations.

The detached signature covers the canonical SHA-256 manifest. The manifest in
turn covers every other regular file in the immutable release, including the
commit/tree/lock/SBOM markers and the signing-key identifier. Public keys are
retained by identifier so an intentional key rotation does not invalidate
rollback releases.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


OPENSSL = Path("/usr/bin/openssl")
KEY_ROOT = Path("/etc/aichat-release-provenance")
PRIVATE_KEY = KEY_ROOT / "private.pem"
PUBLIC_KEY_ROOT = KEY_ROOT / "public"
MANIFEST = ".release-manifest.sha256"
SIGNATURE = ".release-manifest.ed25519"
KEY_ID = ".release-signing-key-id"
KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_RE = re.compile(r"^release-\d{8}T\d{6}_\d+$")
SAFE_PATH_RE = re.compile(r"^(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$")
PYTHON_SAFE_PATH_RE = re.compile(
    r"^(?:[A-Za-z0-9._\[\]-]+/)*[A-Za-z0-9._\[\]-]+$"
)
METADATA = frozenset({MANIFEST, SIGNATURE, KEY_ID})


@dataclass(frozen=True)
class FamilyPolicy:
    root: Path
    max_files: int
    max_bytes: int
    safe_path_re: re.Pattern[str] = SAFE_PATH_RE
    executable_files: frozenset[str] = frozenset()


FAMILIES = {
    "frontend": FamilyPolicy(
        Path("/var/www/aichat-releases"),
        5_000,
        256 * 1024 * 1024,
    ),
    "backend": FamilyPolicy(
        Path("/opt/aichat-backend-releases"),
        5_000,
        128 * 1024 * 1024,
    ),
    "python": FamilyPolicy(
        Path("/opt/aichat-python-envs"),
        20_000,
        512 * 1024 * 1024,
        safe_path_re=PYTHON_SAFE_PATH_RE,
        executable_files=frozenset({"bin/python"}),
    ),
}


class ProvenanceError(RuntimeError):
    """The release or signing boundary is unsafe or inconsistent."""


def _openssl(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    if not OPENSSL.is_file() or OPENSSL.is_symlink():
        raise ProvenanceError("the fixed OpenSSL executable is unavailable")
    try:
        result = subprocess.run(
            [os.fspath(OPENSSL), *arguments],
            input=input_bytes,
            capture_output=True,
            timeout=15,
            check=False,
            env={"LANG": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvenanceError("OpenSSL provenance operation failed") from exc
    if result.returncode:
        raise ProvenanceError("OpenSSL rejected the provenance key or signature")
    return result.stdout


def _regular_file(path: Path, *, uid: int, gid: int, mode: int, size: tuple[int, int]) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProvenanceError(f"required provenance file is unavailable: {path}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != mode
        or not size[0] <= info.st_size <= size[1]
    ):
        raise ProvenanceError(f"unsafe provenance file: {path}")


def _directory(path: Path, *, uid: int, gid: int, mode: int) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ProvenanceError(f"required provenance directory is unavailable: {path}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or path.is_symlink()
        or info.st_uid != uid
        or info.st_gid != gid
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise ProvenanceError(f"unsafe provenance directory: {path}")


def _public_der(path: Path) -> bytes:
    return _openssl("pkey", "-pubin", "-in", os.fspath(path), "-outform", "DER")


def _private_public_der(path: Path) -> bytes:
    return _openssl("pkey", "-in", os.fspath(path), "-pubout", "-outform", "DER")


def active_key_id(
    private_key: Path = PRIVATE_KEY,
    public_key_root: Path = PUBLIC_KEY_ROOT,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> str:
    """Validate the active key boundary and return its SHA-256 public-key ID."""
    _directory(private_key.parent, uid=expected_uid, gid=expected_gid, mode=0o755)
    _directory(public_key_root, uid=expected_uid, gid=expected_gid, mode=0o755)
    _regular_file(
        private_key,
        uid=expected_uid,
        gid=expected_gid,
        mode=0o600,
        size=(64, 4_096),
    )
    private_der = _private_public_der(private_key)
    key_id = hashlib.sha256(private_der).hexdigest()
    public_key = public_key_root / f"{key_id}.pem"
    _regular_file(
        public_key,
        uid=expected_uid,
        gid=expected_gid,
        mode=0o644,
        size=(64, 4_096),
    )
    if _public_der(public_key) != private_der:
        raise ProvenanceError("active private and retained public provenance keys differ")
    return key_id


def _retained_public_key(
    key_id: str,
    public_key_root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> Path:
    if not KEY_ID_RE.fullmatch(key_id):
        raise ProvenanceError("release provenance key ID is malformed")
    _directory(public_key_root, uid=expected_uid, gid=expected_gid, mode=0o755)
    public_key = public_key_root / f"{key_id}.pem"
    _regular_file(
        public_key,
        uid=expected_uid,
        gid=expected_gid,
        mode=0o644,
        size=(64, 4_096),
    )
    if hashlib.sha256(_public_der(public_key)).hexdigest() != key_id:
        raise ProvenanceError("retained provenance public key does not match its ID")
    return public_key


def _release_root_and_tree(
    release: Path,
    policy: FamilyPolicy,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, Path]:
    _directory(policy.root, uid=expected_uid, gid=expected_gid, mode=0o755)
    _directory(release, uid=expected_uid, gid=expected_gid, mode=0o755)
    try:
        root = policy.root.resolve(strict=True)
        resolved = release.resolve(strict=True)
    except OSError as exc:
        raise ProvenanceError("release path cannot be resolved safely") from exc
    if resolved.parent != root or not RELEASE_RE.fullmatch(resolved.name):
        raise ProvenanceError("release leaves its trusted family root")

    files: dict[str, Path] = {}
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(resolved, followlinks=False):
        directory_path = Path(directory)
        _directory(directory_path, uid=expected_uid, gid=expected_gid, mode=0o755)
        for name in dirnames + filenames:
            path = directory_path / name
            relative = path.relative_to(resolved).as_posix()
            if not policy.safe_path_re.fullmatch(relative):
                raise ProvenanceError(f"unsafe release path: {relative}")
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ProvenanceError(f"release contains a symlink: {relative}")
            if info.st_uid != expected_uid or info.st_gid != expected_gid:
                raise ProvenanceError(f"release ownership is unsafe: {relative}")
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o755:
                    raise ProvenanceError(f"release directory mode is unsafe: {relative}")
                continue
            expected_mode = 0o755 if relative in policy.executable_files else 0o644
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != expected_mode:
                raise ProvenanceError(f"release file shape or mode is unsafe: {relative}")
            if relative in files:
                raise ProvenanceError(f"duplicate release path: {relative}")
            files[relative] = path
            total_bytes += info.st_size
            if len(files) > policy.max_files or total_bytes > policy.max_bytes:
                raise ProvenanceError("release exceeds its family file or byte bound")
    if not files:
        raise ProvenanceError("refusing an empty release")
    return files


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _exclusive_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    path.chmod(mode)


def _manifest_bytes(files: dict[str, Path]) -> bytes:
    covered = sorted(path for path in files if path not in {MANIFEST, SIGNATURE})
    if KEY_ID not in covered:
        raise ProvenanceError("release signing-key marker is not covered")
    return "".join(
        f"{_hash_file(files[relative])}  ./{relative}\n" for relative in covered
    ).encode("ascii")


def sign_release(
    release: Path,
    policy: FamilyPolicy,
    *,
    private_key: Path = PRIVATE_KEY,
    public_key_root: Path = PUBLIC_KEY_ROOT,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> str:
    """Sign a new immutable release and return its retained public-key ID."""
    files = _release_root_and_tree(
        release,
        policy,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if METADATA.intersection(files):
        raise ProvenanceError("refusing to replace existing release provenance metadata")
    key_id = active_key_id(
        private_key,
        public_key_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    created: list[Path] = []
    try:
        key_id_path = release / KEY_ID
        _exclusive_write(key_id_path, f"{key_id}\n".encode("ascii"))
        created.append(key_id_path)
        files = _release_root_and_tree(
            release,
            policy,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        manifest_path = release / MANIFEST
        _exclusive_write(manifest_path, _manifest_bytes(files))
        created.append(manifest_path)
        signature = _openssl(
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            os.fspath(private_key),
            "-in",
            os.fspath(manifest_path),
        )
        if len(signature) != 64:
            raise ProvenanceError("Ed25519 release signature has an unexpected size")
        signature_path = release / SIGNATURE
        _exclusive_write(signature_path, signature)
        created.append(signature_path)
        verify_release(
            release,
            policy,
            public_key_root=public_key_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        return key_id
    except Exception:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _parse_manifest(manifest: Path) -> dict[str, str]:
    try:
        raw = manifest.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ProvenanceError("release manifest is unreadable") from exc
    if not raw.endswith("\n") or len(raw.encode("ascii")) > 4 * 1024 * 1024:
        raise ProvenanceError("release manifest shape is unsafe")
    hashes: dict[str, str] = {}
    order: list[str] = []
    for line in raw.splitlines():
        digest, separator, relative = line.partition("  ./")
        if (
            separator != "  ./"
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or not relative
            or relative in hashes
        ):
            raise ProvenanceError("release manifest contains an invalid entry")
        hashes[relative] = digest
        order.append(relative)
    if not hashes or order != sorted(order):
        raise ProvenanceError("release manifest is empty or non-canonical")
    return hashes


def verify_release(
    release: Path,
    policy: FamilyPolicy,
    *,
    public_key_root: Path = PUBLIC_KEY_ROOT,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> str:
    """Verify release completeness, hashes, retained key ID, and signature."""
    files = _release_root_and_tree(
        release,
        policy,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if not METADATA.issubset(files):
        raise ProvenanceError("signed release provenance metadata is incomplete")
    manifest_path = files[MANIFEST]
    signature_path = files[SIGNATURE]
    key_id_path = files[KEY_ID]
    if signature_path.stat().st_size != 64 or key_id_path.stat().st_size != 65:
        raise ProvenanceError("release signature or key ID has an unsafe size")
    try:
        key_id = key_id_path.read_text(encoding="ascii").removesuffix("\n")
    except (OSError, UnicodeError) as exc:
        raise ProvenanceError("release signing-key marker is unreadable") from exc
    public_key = _retained_public_key(
        key_id,
        public_key_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    expected_hashes = _parse_manifest(manifest_path)
    covered_files = {path: file for path, file in files.items() if path not in {MANIFEST, SIGNATURE}}
    if set(expected_hashes) != set(covered_files):
        raise ProvenanceError("release manifest does not exactly cover the release")
    for relative, digest in expected_hashes.items():
        if _hash_file(covered_files[relative]) != digest:
            raise ProvenanceError("release content differs from its signed manifest")
    _openssl(
        "pkeyutl",
        "-verify",
        "-rawin",
        "-pubin",
        "-inkey",
        os.fspath(public_key),
        "-in",
        os.fspath(manifest_path),
        "-sigfile",
        os.fspath(signature_path),
    )
    return key_id


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("sign", "verify"):
        command = subparsers.add_parser(operation)
        command.add_argument("--family", choices=sorted(FAMILIES), required=True)
        command.add_argument("--release", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "sign" and os.geteuid() != 0:
        parser.error("release provenance signing must run as root")
    try:
        if args.operation == "sign":
            key_id = sign_release(args.release, FAMILIES[args.family])
            print(f"Signed {args.family} release with key {key_id}")
        else:
            key_id = verify_release(args.release, FAMILIES[args.family])
            print(f"Verified {args.family} release with key {key_id}")
    except ProvenanceError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
