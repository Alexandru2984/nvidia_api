#!/usr/bin/env python3
"""Regression tests for signed immutable release provenance."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import release_provenance as provenance

ROOT = Path(__file__).resolve().parents[1]


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release_root = self.root / "releases"
        self.release = self.release_root / "release-20261020T010203_123456789"
        self.release.mkdir(parents=True, mode=0o755)
        self.release_root.chmod(0o755)
        self.release.chmod(0o755)
        self.payload = self.release / "assets" / "application.js"
        self.payload.parent.mkdir(mode=0o755)
        self.payload.write_text("trusted release\n", encoding="utf-8")
        self.payload.chmod(0o644)

        self.key_root = self.root / "keys"
        self.public_root = self.key_root / "public"
        self.public_root.mkdir(parents=True, mode=0o755)
        self.key_root.chmod(0o755)
        self.public_root.chmod(0o755)
        self.private_key = self.key_root / "private.pem"
        self.key_id = self._generate_key(self.private_key)
        self.policy = provenance.FamilyPolicy(
            self.release_root,
            max_files=20,
            max_bytes=1024 * 1024,
        )
        self.uid = os.getuid()
        self.gid = os.getgid()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _openssl(self, *arguments: str) -> bytes:
        result = subprocess.run(
            [str(provenance.OPENSSL), *arguments],
            capture_output=True,
            check=True,
        )
        return result.stdout

    def _generate_key(self, private_key: Path) -> str:
        self._openssl("genpkey", "-algorithm", "ED25519", "-out", str(private_key))
        private_key.chmod(0o600)
        public_der = self._openssl(
            "pkey", "-in", str(private_key), "-pubout", "-outform", "DER"
        )
        key_id = hashlib.sha256(public_der).hexdigest()
        public_key = self.public_root / f"{key_id}.pem"
        self._openssl(
            "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)
        )
        public_key.chmod(0o644)
        return key_id

    def sign(self) -> str:
        return provenance.sign_release(
            self.release,
            self.policy,
            private_key=self.private_key,
            public_key_root=self.public_root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def verify(self) -> str:
        return provenance.verify_release(
            self.release,
            self.policy,
            public_key_root=self.public_root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def test_signs_and_verifies_exact_release(self) -> None:
        self.assertEqual(self.sign(), self.key_id)
        self.assertEqual(self.verify(), self.key_id)
        manifest = (self.release / provenance.MANIFEST).read_text(encoding="ascii")
        self.assertIn(f"./{provenance.KEY_ID}\n", manifest)
        self.assertNotIn(provenance.SIGNATURE, manifest)
        self.assertEqual((self.release / provenance.SIGNATURE).stat().st_size, 64)

    def test_rejects_content_tampering(self) -> None:
        self.sign()
        self.payload.write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(provenance.ProvenanceError):
            self.verify()

    def test_rejects_manifest_or_signature_tampering(self) -> None:
        self.sign()
        signature = self.release / provenance.SIGNATURE
        signature.write_bytes(bytes([signature.read_bytes()[0] ^ 1]) + signature.read_bytes()[1:])
        signature.chmod(0o644)
        with self.assertRaises(provenance.ProvenanceError):
            self.verify()

    def test_rejects_unlisted_files(self) -> None:
        self.sign()
        injected = self.release / "injected.js"
        injected.write_text("unexpected\n", encoding="utf-8")
        injected.chmod(0o644)
        with self.assertRaises(provenance.ProvenanceError):
            self.verify()

    def test_rejects_missing_or_wrong_retained_key(self) -> None:
        self.sign()
        (self.public_root / f"{self.key_id}.pem").unlink()
        with self.assertRaises(provenance.ProvenanceError):
            self.verify()

    def test_rejects_unsafe_release_or_private_key_modes(self) -> None:
        self.payload.chmod(0o664)
        with self.assertRaises(provenance.ProvenanceError):
            self.sign()
        self.payload.chmod(0o644)
        self.private_key.chmod(0o640)
        with self.assertRaises(provenance.ProvenanceError):
            self.sign()

    def test_refuses_to_replace_existing_provenance(self) -> None:
        self.sign()
        with self.assertRaises(provenance.ProvenanceError):
            self.sign()

    def test_retained_public_key_preserves_old_release_after_rotation(self) -> None:
        self.sign()
        rotated_private = self.key_root / "rotated.pem"
        rotated_id = self._generate_key(rotated_private)
        rotated_private.replace(self.private_key)
        self.private_key.chmod(0o600)
        self.assertNotEqual(rotated_id, self.key_id)
        self.assertEqual(self.verify(), self.key_id)

    def test_all_release_paths_sign_or_verify_with_the_common_tool(self) -> None:
        frontend = (ROOT / "scripts/deploy_frontend.sh").read_text(encoding="utf-8")
        backend = (ROOT / "scripts/deploy_backend.sh").read_text(encoding="utf-8")
        python = (ROOT / "scripts/deploy_python_env.sh").read_text(encoding="utf-8")
        rollback = (ROOT / "scripts/release_rollback_drill.sh").read_text(
            encoding="utf-8"
        )
        monitor = (ROOT / "scripts/security_monitor.py").read_text(encoding="utf-8")
        for family, source in (
            ("frontend", frontend),
            ("backend", backend),
            ("python", python),
        ):
            self.assertIn(f"sign --family {family}", source)
            self.assertIn(f"verify --family {family}", source)
        self.assertIn('verify --family "$family"', rollback)
        self.assertIn("require_release_provenance=True", monitor)

    def test_key_installer_keeps_private_key_root_only_and_serializes_rotation(self) -> None:
        installer = (ROOT / "scripts/install_release_provenance.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("PRIVATE_KEY=\"$KEY_ROOT/private.pem\"", installer)
        self.assertIn("LOCK_FILE='/run/aichat-release-operation.lock'", installer)
        self.assertIn("flock -n 9", installer)
        self.assertIn("-m 0600 -- \"$new_private\"", installer)
        self.assertIn("-m 0644 -- \"$new_public\"", installer)
        self.assertIn("--rotate", installer)


if __name__ == "__main__":
    unittest.main()
