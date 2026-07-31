#!/usr/bin/env python3
"""Contract tests for Console local-sidecar release imports."""
from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import console_local_sidecar as sidecar


SOURCE = {
    "commit": "a" * 40,
    "tree": "b" * 40,
    "version": "0.2.0",
    "package_lock_sha256": "c" * 64,
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_file(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    archive.addfile(info, io.BytesIO(data))


def build_target(root: Path, target: str) -> dict[str, object]:
    os_name, arch = target.split("-", 1)
    archive_name = f"helm-console-local-sidecar-{target}.tar.gz"
    payload = {
        "app/helm-local-sidecar.mjs": b"launcher",
        "runtime/node/LICENSE": b"license",
        "runtime/node/bin/node": b"node-runtime",
    }
    inventory = "".join(f"{digest(payload[name])}  {name}\n" for name in sorted(payload)).encode()
    libc = {"family": "libSystem", "version": "host-reported-unavailable"} if os_name == "darwin" else {"family": "glibc", "version": "2.39"}
    provenance_core = {
        "schema": sidecar.INNER_PROVENANCE_SCHEMA,
        "target": {"os": os_name, "arch": arch},
        "build": sidecar.BUILD_CONTRACT,
        "source": SOURCE,
        "runtime": {
            "node": "22.16.0",
            "bundled_node": {"executable": "runtime/node/bin/node", "license_notice": "runtime/node/LICENSE"},
            "npm": "10.9.2",
            "next": "15.4.2",
            "platform": {"os": os_name, "arch": arch, "target": target},
            "libc": libc,
        },
        "bundle_sha256": digest(inventory),
        "inventory": "INVENTORY.sha256",
        "bundle_hash_scope": sidecar.BUNDLE_HASH_SCOPE,
        "signature": "none; this unsigned local artifact has no release authority",
    }
    closure_root = f"helm-console-local-sidecar-{target}"
    artifact_dir = root / f"artifact-{target}"
    artifact_dir.mkdir()
    archive = artifact_dir / archive_name
    with tarfile.open(archive, "w:gz") as output:
        for name, data in payload.items():
            write_file(output, f"{closure_root}/{name}", data, 0o755 if name.endswith("/node") else 0o644)
        write_file(output, f"{closure_root}/INVENTORY.sha256", inventory)
        embedded_provenance_bytes = (json.dumps(provenance_core, sort_keys=True) + "\n").encode()
        write_file(output, f"{closure_root}/PROVENANCE.json", embedded_provenance_bytes)

    archive_bytes = archive.read_bytes()
    provenance = {
        **provenance_core,
        "archive": {"file": archive_name, "sha256": digest(archive_bytes)},
    }
    provenance_bytes = (json.dumps(provenance, sort_keys=True) + "\n").encode()
    descriptor = f"{digest(archive_bytes)}  {archive_name}\n".encode()
    inventory_path = artifact_dir / f"{archive_name}.inventory.sha256"
    provenance_path = artifact_dir / f"{archive_name}.provenance.json"
    checksum_path = artifact_dir / f"{archive_name}.sha256"
    inventory_path.write_bytes(inventory)
    provenance_path.write_bytes(provenance_bytes)
    checksum_path.write_bytes(descriptor)
    return {
        "target": {"os": os_name, "arch": arch},
        "inner_artifact": {
            "provenance_schema": "helm.console.local-sidecar.provenance.v1",
            "signature": provenance_core["signature"],
            "release_authority": False,
            "bundle_sha256": digest(inventory),
        },
        "artifacts": {
            "archive": {"file": archive.name, "sha256": digest(archive_bytes)},
            "archive_checksum": {"file": checksum_path.name, "sha256": digest(descriptor)},
            "inventory": {"file": inventory_path.name, "sha256": digest(inventory)},
            "provenance": {"file": provenance_path.name, "sha256": digest(provenance_bytes)},
        },
    }


def build_release(root: Path) -> tuple[Path, Path]:
    targets = [build_target(root, target) for target in sidecar.TARGETS]
    manifest = {
        "schema": sidecar.MANIFEST_SCHEMA,
        "component": sidecar.COMPONENT,
        "source_repository": sidecar.CONSOLE_REPOSITORY,
        "kernel_release_version": "v0.8.0",
        "source": SOURCE,
        "targets": targets,
        "outer_signature": {
            "signed_file": sidecar.MANIFEST_NAME,
            "bundle": sidecar.MANIFEST_BUNDLE_NAME,
            "issuer": sidecar.COSIGN_ISSUER,
            "certificate_identity": sidecar.COSIGN_IDENTITY,
        },
    }
    manifest_dir = root / "aggregate"
    manifest_dir.mkdir()
    (manifest_dir / sidecar.MANIFEST_NAME).write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    (manifest_dir / sidecar.MANIFEST_BUNDLE_NAME).write_text("test-only bundle", encoding="utf-8")
    pins = root / "pins.json"
    pins.write_text(json.dumps({
        "schema": sidecar.PINS_SCHEMA,
        "pins": [{
            "kernel_release_version": "v0.8.0",
            "source_repository": sidecar.CONSOLE_REPOSITORY,
            "source": SOURCE,
        }],
    }), encoding="utf-8")
    return root, pins


class ConsoleLocalSidecarTests(unittest.TestCase):
    def test_valid_pinned_release_stages_all_verified_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            verified = sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)
            self.assertEqual(len(verified), 18)
            output = root / "staged"
            copied = sidecar.stage_release(root, output, pins, "v0.8.0", require_cosign=False)
            self.assertEqual({path.name for path in copied}, {path.name for path in verified})
            self.assertTrue((output / sidecar.MANIFEST_NAME).is_file())

    def test_release_rejects_unpinned_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            pins.write_text(json.dumps({"schema": sidecar.PINS_SCHEMA, "pins": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one Console source pin"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_checksum_descriptor_that_does_not_bind_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            checksum = next(root.rglob("helm-console-local-sidecar-darwin-arm64.tar.gz.sha256"))
            checksum.write_text(f"{'0' * 64}  helm-console-local-sidecar-darwin-arm64.tar.gz\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "archive_checksum hash"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_inner_release_authority_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            manifest = next(root.rglob(sidecar.MANIFEST_NAME))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["targets"][0]["inner_artifact"]["release_authority"] = True
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must not claim inner release authority"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_out_of_order_native_targets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            manifest = next(root.rglob(sidecar.MANIFEST_NAME))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["targets"] = list(reversed(payload["targets"]))
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "ordered exactly"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_kernel_cosign_verifier_preserves_the_console_producer_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / "artifacts"
            artifacts.mkdir()
            manifest = artifacts / sidecar.MANIFEST_NAME
            manifest.write_text("manifest", encoding="utf-8")
            (artifacts / sidecar.MANIFEST_BUNDLE_NAME).write_text("producer", encoding="utf-8")
            (artifacts / f"{sidecar.MANIFEST_NAME}.kernel.cosign.bundle").write_text("kernel", encoding="utf-8")
            (artifacts / "ordinary-release-asset").write_text("asset", encoding="utf-8")
            (artifacts / "ordinary-release-asset.cosign.bundle").write_text("kernel", encoding="utf-8")
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_cosign = fake_bin / "cosign"
            fake_cosign.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            fake_cosign.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            result = subprocess.run(
                ["bash", str(REPOSITORY_ROOT / "scripts/release/verify_cosign.sh"), str(artifacts)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("skipping Console producer bundle", result.stdout)
            self.assertIn("verified=2 failed=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
