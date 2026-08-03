#!/usr/bin/env python3
"""Contract tests for Console local-sidecar release imports.

quantum_posture: tests classical SHA-256 and Cosign release evidence only; they
make no post-quantum assurance claim.
"""
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
from unittest.mock import patch

import console_local_sidecar as sidecar


SOURCE = {
    "commit": "a" * 40,
    "tree": "b" * 40,
    "version": "0.2.0",
    "package_lock_sha256": "c" * 64,
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_SOURCE_PIN = {
    "commit": "8965520b71f4d23c0974b176f0e1cbb3877d5c33",
    "tree": "fa89304740e04f079d28bb507c86b6a1716484da",
    "version": "0.2.1",
    "package_lock_sha256": "1028990307789189333657942de79d11e6889ef47dc539f77e0a9c94c26a2076",
}
RELEASE_WORKFLOW_REF = "refs/tags/helm-console-sidecar-v0.8.0"
TEST_WORKFLOW_REF = "refs/tags/test-console-source"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_file(
    archive: tarfile.TarFile,
    name: str,
    data: bytes,
    mode: int = 0o644,
    *,
    member_type: bytes = tarfile.REGTYPE,
    linkname: str = "",
) -> None:
    info = tarfile.TarInfo(name)
    info.type = member_type
    info.linkname = linkname
    info.size = len(data)
    info.mode = mode
    archive.addfile(info, io.BytesIO(data))


def write_directory(archive: tarfile.TarFile, name: str, *, linkname: str = "") -> None:
    info = tarfile.TarInfo(f"{name}/")
    info.type = tarfile.DIRTYPE
    info.linkname = linkname
    info.mode = 0o755
    archive.addfile(info)


def build_target(
    root: Path,
    target: str,
    *,
    mutate_inventory: callable | None = None,
    mutate_provenance: callable | None = None,
) -> dict[str, object]:
    os_name, arch = target.split("-", 1)
    archive_name = f"helm-console-local-sidecar-{target}.tar.gz"
    payload = {
        "app/helm-local-sidecar.mjs": b"launcher",
        "runtime/node/LICENSE": b"license",
        "runtime/node/bin/node": b"node-runtime",
    }
    inventory = "".join(f"{digest(payload[name])}  {name}\n" for name in sorted(payload)).encode()
    if mutate_inventory is not None:
        inventory = mutate_inventory(inventory)
    libc = {"family": "libSystem", "version": "host-reported-unavailable"} if os_name == "darwin" else {"family": "glibc", "version": "2.39"}
    provenance_core = {
        "schema": sidecar.INNER_PROVENANCE_SCHEMA,
        "target": {"os": os_name, "arch": arch},
        "build": sidecar.BUILD_CONTRACT,
        "source": SOURCE,
        "runtime": {
            "node": "v22.16.0",
            "bundled_node": {"executable": "runtime/node/bin/node", "license_notice": "runtime/node/LICENSE"},
            "npm": "10.9.2",
            "next": "15.4.2",
            "platform": {"os": os_name, "arch": arch, "target": target},
            "libc": libc,
        },
        "bundle_sha256": digest(inventory),
        "inventory": "INVENTORY.sha256",
        "bundle_hash_scope": sidecar.BUNDLE_HASH_SCOPE,
        "signature": sidecar.UNSIGNED_INNER_SIGNATURE,
    }
    if mutate_provenance is not None:
        provenance_core = mutate_provenance(provenance_core)
    closure_root = f"helm-console-local-sidecar-{target}"
    artifact_dir = root / f"artifact-{target}"
    artifact_dir.mkdir()
    archive = artifact_dir / archive_name
    with tarfile.open(archive, "w:gz") as output:
        # Match the canonical directory entries produced by the Console
        # packager's `tar -czf -C <parent> <closure-root>` invocation.
        for directory in (
            closure_root,
            f"{closure_root}/app",
            f"{closure_root}/runtime",
            f"{closure_root}/runtime/node",
            f"{closure_root}/runtime/node/bin",
        ):
            write_directory(output, directory)
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


def build_release(root: Path, *, target_mutators: dict[str, dict[str, object]] | None = None) -> tuple[Path, Path]:
    target_mutators = target_mutators or {}
    targets = [build_target(root, target, **target_mutators.get(target, {})) for target in sidecar.TARGETS]
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
            "certificate_identity": sidecar.console_cosign_identity(TEST_WORKFLOW_REF),
        },
    }
    manifest_dir = root / "aggregate"
    manifest_dir.mkdir()
    (manifest_dir / sidecar.MANIFEST_NAME).write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    (manifest_dir / sidecar.MANIFEST_BUNDLE_NAME).write_text("test-only bundle", encoding="utf-8")
    (manifest_dir / sidecar.KERNEL_MANIFEST_BUNDLE_NAME).write_text("test-only Kernel bundle", encoding="utf-8")
    pins = root / "pins.json"
    pins.write_text(json.dumps({
        "schema": sidecar.PINS_SCHEMA,
        "pins": [{
            "kernel_release_version": "v0.8.0",
            "source_repository": sidecar.CONSOLE_REPOSITORY,
            "source": SOURCE,
            "workflow_ref": TEST_WORKFLOW_REF,
        }],
    }), encoding="utf-8")
    return root, pins


def manifest_digest(root: Path) -> str:
    return sidecar.sha256_path(next(root.rglob(sidecar.MANIFEST_NAME)))


def write_kernel_binaries(root: Path) -> None:
    for target, name in sidecar.KERNEL_BINARY_NAMES.items():
        path = root / name
        path.write_bytes(f"kernel binary for {target}\n".encode())
        path.chmod(0o755)


class ConsoleLocalSidecarTests(unittest.TestCase):
    def test_inventory_rejects_runtime_incompatible_line_endings(self) -> None:
        inventory = f"{'0' * 64}  app/helm-local-sidecar.mjs\n".encode()
        for label, value in {
            "missing-final-lf": inventory[:-1],
            "crlf": inventory.replace(b"\n", b"\r\n"),
        }.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, "closure inventory is invalid"):
                sidecar.parse_inventory(value)

    def test_runtime_provenance_values_match_launcher_validation(self) -> None:
        target = {"os": "linux", "arch": "amd64"}
        runtime = {
            "node": "v22.16.0",
            "bundled_node": {"executable": "runtime/node/bin/node", "license_notice": "runtime/node/LICENSE"},
            "npm": "10.9.2",
            "next": "15.4.2",
            "platform": {"os": "linux", "arch": "amd64", "target": "linux-amd64"},
            "libc": {"family": "glibc", "version": "2.39"},
        }
        mutations = {
            "node": "v22.16.0 ",
            "npm": "10.9.2\t",
            "next": "15.4.2\x00",
            "libc.version": "é" * 257,
        }
        for field, invalid in mutations.items():
            with self.subTest(field=field):
                candidate = json.loads(json.dumps(runtime))
                if field == "libc.version":
                    candidate["libc"]["version"] = invalid
                else:
                    candidate[field] = invalid
                with self.assertRaisesRegex(ValueError, "trimmed string|control characters"):
                    sidecar.verify_runtime(candidate, target)
        candidate = json.loads(json.dumps(runtime))
        candidate["npm"] = "10.9.2\u200d"
        sidecar.verify_runtime(candidate, target)

    def test_target_rejects_oversized_external_metadata_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, _ = build_release(Path(directory))
            manifest = json.loads(next(root.rglob(sidecar.MANIFEST_NAME)).read_text(encoding="utf-8"))
            original_sha256_path = sidecar.sha256_path

            def archive_only_hash(path: Path) -> str:
                if path.name.endswith(".tar.gz"):
                    return original_sha256_path(path)
                raise AssertionError(f"metadata was hashed before its size check: {path.name}")

            with patch.object(sidecar, "INVENTORY_MAX_BYTES", 1), patch.object(sidecar, "sha256_path", side_effect=archive_only_hash):
                with self.assertRaisesRegex(ValueError, "archive_checksum exceeds the validation limit"):
                    sidecar.verify_target(root, manifest["targets"][0], SOURCE)

    def test_archive_bounds_match_launcher_during_verification_and_assembly(self) -> None:
        target = "linux-amd64"
        closure_root = f"helm-console-local-sidecar-{target}"
        target_value = {"os": "linux", "arch": "amd64"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aggregate = root / "aggregate.tar.gz"
            with tarfile.open(aggregate, "w:gz") as output:
                write_file(output, f"{closure_root}/app/too-large", b"\0" * 1025)
            with patch.object(sidecar, "BUNDLE_MAX_BYTES", 1024):
                self.assertLess(aggregate.stat().st_size, sidecar.BUNDLE_MAX_BYTES)
                with self.assertRaisesRegex(ValueError, "archive payload exceeds the validation limit"):
                    sidecar.verify_archive(aggregate, b"", b"{}", "0" * 64, SOURCE, target_value, {})
                with self.assertRaisesRegex(ValueError, "archive payload exceeds the validation limit"), tarfile.open(root / "aggregate.tar", "w") as output:
                    sidecar.tar_verified_target_tree(output, aggregate, target, "layout")

            compressed = root / "compressed.tar.gz"
            with tarfile.open(compressed, "w:gz") as output:
                write_file(output, f"{closure_root}/app/compressed", bytes(range(128)))
            with patch.object(sidecar, "BUNDLE_MAX_BYTES", 32):
                self.assertGreater(compressed.stat().st_size, sidecar.BUNDLE_MAX_BYTES)
                with self.assertRaisesRegex(ValueError, "sidecar archive exceeds the validation limit"):
                    sidecar.verify_archive(compressed, b"", b"{}", "0" * 64, SOURCE, target_value, {})
                with self.assertRaisesRegex(ValueError, "verified sidecar archive exceeds the validation limit"), tarfile.open(root / "compressed.tar", "w") as output:
                    sidecar.tar_verified_target_tree(output, compressed, target, "layout")

    def test_archive_rejects_runtime_unsupported_member_forms(self) -> None:
        target = "linux-amd64"
        closure_root = f"helm-console-local-sidecar-{target}"
        target_value = {"os": "linux", "arch": "amd64"}
        cases = {
            "linked-directory": lambda archive: write_directory(archive, closure_root, linkname="elsewhere"),
            "linked-regular": lambda archive: write_file(archive, f"{closure_root}/app/file", b"payload", linkname="elsewhere"),
            "contiguous": lambda archive: write_file(archive, f"{closure_root}/app/file", b"payload", member_type=tarfile.CONTTYPE),
            "gnu-sparse": lambda archive: write_file(archive, f"{closure_root}/app/file", b"payload", member_type=tarfile.GNUTYPE_SPARSE),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, add_member in cases.items():
                source = root / f"{label}.tar.gz"
                with tarfile.open(source, "w:gz") as input_archive:
                    add_member(input_archive)
                with self.subTest(label=label):
                    with self.assertRaisesRegex(ValueError, "unsupported|link metadata"):
                        sidecar.verify_archive(source, b"", b"{}", "0" * 64, SOURCE, target_value, {})
                    with self.assertRaisesRegex(ValueError, "unsupported|link metadata"), tarfile.open(root / f"{label}.tar", "w") as output_archive:
                        sidecar.tar_verified_target_tree(output_archive, source, target, "layout")

    def test_archive_rejects_invalid_gzip_trailer_before_staging(self) -> None:
        target = "linux-amd64"
        closure_root = f"helm-console-local-sidecar-{target}"
        target_value = {"os": "linux", "arch": "amd64"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "trailer.tar.gz"
            with tarfile.open(source, "w:gz") as input_archive:
                write_file(input_archive, f"{closure_root}/app/file", b"payload")
            source.write_bytes(source.read_bytes() + b"not-a-gzip-member")
            with self.assertRaisesRegex(ValueError, "gzip stream is invalid"):
                sidecar.verify_archive(source, b"", b"{}", "0" * 64, SOURCE, target_value, {})
            with self.assertRaisesRegex(ValueError, "gzip stream is invalid"), tarfile.open(root / "trailer.tar", "w") as output_archive:
                sidecar.tar_verified_target_tree(output_archive, source, target, "layout")

    def test_release_accepts_canonical_console_packager_directory_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            # build_target writes explicit `root/` directory records, exactly
            # as the native Console release packager does.
            verified = sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)
            self.assertEqual(len(verified), 18)

    def test_valid_pinned_release_stages_all_verified_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            verified = sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)
            self.assertEqual(len(verified), 18)
            output = root / "staged"
            copied = sidecar.stage_release(
                root,
                output,
                pins,
                "v0.8.0",
                require_cosign=False,
                expected_manifest_sha256=manifest_digest(root),
            )
            self.assertEqual(
                {path.name for path in copied},
                {path.name for path in [*verified, next(root.rglob(sidecar.KERNEL_MANIFEST_BUNDLE_NAME))]},
            )
            self.assertTrue((output / sidecar.MANIFEST_NAME).is_file())

    def test_release_layouts_package_the_verified_console_tree_next_to_each_kernel_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            assets = root / "release-assets"
            copied = sidecar.stage_release(
                root,
                assets,
                pins,
                "v0.8.0",
                require_cosign=False,
                expected_manifest_sha256=manifest_digest(root),
            )
            write_kernel_binaries(assets)
            layouts = sidecar.package_release_layouts(
                assets,
                assets,
                pins,
                "v0.8.0",
                require_cosign=False,
                expected_manifest_sha256=manifest_digest(root),
            )
            first = {path.name: path.read_bytes() for path in layouts}
            repeated = sidecar.package_release_layouts(
                assets,
                assets,
                pins,
                "v0.8.0",
                require_cosign=False,
                expected_manifest_sha256=manifest_digest(root),
            )
            self.assertEqual(first, {path.name: path.read_bytes() for path in repeated})

            raw_names = {path.name for path in copied}
            for target, layout in zip(sidecar.TARGETS, layouts):
                root_name = sidecar.layout_root_name(target)
                with tarfile.open(layout, "r:gz") as archive:
                    names = set(archive.getnames())
                    self.assertIn(f"{root_name}/helm-ai-kernel", names)
                    self.assertLessEqual(raw_names, {name.removeprefix(f"{root_name}/console/") for name in names})
                    self.assertIn(
                        f"{root_name}/console/helm-console-local-sidecar-{target}/app/helm-local-sidecar.mjs",
                        names,
                    )
                    kernel = archive.extractfile(f"{root_name}/helm-ai-kernel")
                    self.assertIsNotNone(kernel)
                    self.assertEqual(kernel.read(), f"kernel binary for {target}\n".encode())

    def test_release_layout_packager_rejects_traversal_and_duplicate_archive_members(self) -> None:
        target = "linux-amd64"
        closure_root = f"helm-console-local-sidecar-{target}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "traversal": [("../outside", b"escape")],
                "duplicate": [
                    (f"{closure_root}/app/helm-local-sidecar.mjs", b"one"),
                    (f"{closure_root}/app/helm-local-sidecar.mjs", b"two"),
                ],
            }
            for label, members in cases.items():
                source = root / f"{label}.tar.gz"
                with tarfile.open(source, "w:gz") as input_archive:
                    for name, payload in members:
                        write_file(input_archive, name, payload)
                with self.subTest(label=label), tarfile.open(root / f"{label}.tar", "w") as output_archive:
                    with self.assertRaisesRegex(ValueError, "unsafe path|duplicate member path"):
                        sidecar.tar_verified_target_tree(output_archive, source, target, "layout")

    def test_release_staging_requires_the_kernel_manifest_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            next(root.rglob(sidecar.KERNEL_MANIFEST_BUNDLE_NAME)).unlink()
            with self.assertRaisesRegex(ValueError, "Kernel aggregate manifest cosign bundle"):
                sidecar.stage_release(
                    root,
                    root / "staged",
                    pins,
                    "v0.8.0",
                    require_cosign=False,
                    expected_manifest_sha256=manifest_digest(root),
                )

    def test_release_staging_requires_a_compiled_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            with self.assertRaisesRegex(ValueError, "requires the expected Console aggregate manifest SHA-256"):
                sidecar.stage_release(
                    root,
                    root / "staged",
                    pins,
                    "v0.8.0",
                    require_cosign=False,
                    expected_manifest_sha256=None,
                )

    def test_release_rejects_tampered_or_missing_aggregate_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            manifest = next(root.rglob(sidecar.MANIFEST_NAME))
            expected = manifest_digest(root)
            manifest.write_text(manifest.read_text(encoding="utf-8") + " ", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match the expected compiled digest"):
                sidecar.verify_release(
                    root,
                    pins,
                    "v0.8.0",
                    require_cosign=False,
                    expected_manifest_sha256=expected,
                )
            manifest.unlink()
            with self.assertRaisesRegex(ValueError, "exactly one Console aggregate release manifest"):
                sidecar.verify_release(
                    root,
                    pins,
                    "v0.8.0",
                    require_cosign=False,
                    expected_manifest_sha256=expected,
                )

    def test_release_rejects_unpinned_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            pins.write_text(json.dumps({"schema": sidecar.PINS_SCHEMA, "pins": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one Console source pin"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_missing_or_mutable_workflow_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            payload = json.loads(pins.read_text(encoding="utf-8"))
            for label, workflow_ref in (("missing", None), ("main", "main"), ("branch", "refs/heads/main")):
                with self.subTest(label=label):
                    candidate = json.loads(json.dumps(payload))
                    pin = candidate["pins"][0]
                    if workflow_ref is None:
                        del pin["workflow_ref"]
                    else:
                        pin["workflow_ref"] = workflow_ref
                    pins.write_text(json.dumps(candidate), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "workflow_ref|invalid fields"):
                        sidecar.resolve_pin(pins, "v0.8.0")

    def test_release_rejects_outer_signature_not_bound_to_pinned_workflow_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            manifest = next(root.rglob(sidecar.MANIFEST_NAME))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["outer_signature"]["certificate_identity"] = sidecar.console_cosign_identity(
                "refs/tags/other-console-source"
            )
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected outer signature contract"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_checksum_descriptor_that_does_not_bind_archive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            checksum = next(root.rglob("helm-console-local-sidecar-darwin-arm64.tar.gz.sha256"))
            checksum.write_text(f"{'0' * 64}  helm-console-local-sidecar-darwin-arm64.tar.gz\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "archive_checksum hash"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_console_inventory_without_runtime_newline_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(
                Path(directory),
                target_mutators={"linux-amd64": {"mutate_inventory": lambda data: data.rstrip(b"\n")}},
            )
            with self.assertRaisesRegex(ValueError, "closure inventory is invalid"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_console_provenance_runtime_values_the_launcher_would_reject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(
                Path(directory),
                target_mutators={"linux-amd64": {"mutate_provenance": lambda data: {**data, "runtime": {**data["runtime"], "npm": "10.9.2 "}}}},
            )
            with self.assertRaisesRegex(ValueError, "runtime.npm must be a trimmed string"):
                sidecar.verify_release(root, pins, "v0.8.0", require_cosign=False)

    def test_release_rejects_console_archives_over_the_runtime_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            with patch.object(sidecar, "BUNDLE_MAX_BYTES", 32):
                with self.assertRaisesRegex(ValueError, "validation limit|release limit|runtime size limit"):
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

    def test_release_rejects_noncanonical_unsigned_inner_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, pins = build_release(Path(directory))
            manifest = next(root.rglob(sidecar.MANIFEST_NAME))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["targets"][0]["inner_artifact"]["signature"] = "none; unexpected state"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected unsigned inner artifact signature"):
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

    def test_v080_source_pin_matches_the_exact_console_release_contract(self) -> None:
        pin = sidecar.resolve_pin(
            REPOSITORY_ROOT / "release/console-local-sidecar-pins.json",
            "v0.8.0",
        )
        self.assertEqual(pin["source_repository"], sidecar.CONSOLE_REPOSITORY)
        self.assertEqual(pin["source"], RELEASE_SOURCE_PIN)
        self.assertEqual(pin["workflow_ref"], RELEASE_WORKFLOW_REF)

    def test_manifest_digest_flows_into_normal_and_reproducible_linker_flags(self) -> None:
        expected_digest = "d" * 64
        env = os.environ.copy()
        env.pop("GOROOT", None)
        env["PATH"] = "/opt/homebrew/bin:/usr/bin:/bin"
        result = subprocess.run(
            ["make", "-pn", f"CONSOLE_LOCAL_SIDECAR_MANIFEST_SHA256={expected_digest}"],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, rf"(?m)^LDFLAGS := .*main\.consoleLocalSidecarManifestSHA256={expected_digest}$")
        self.assertRegex(result.stdout, rf"(?m)^REPRO_LDFLAGS := .*main\.consoleLocalSidecarManifestSHA256={expected_digest}$")

    def test_kernel_cosign_verifier_derives_exact_tag_and_checks_both_console_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / "artifacts"
            artifacts.mkdir()
            manifest = artifacts / sidecar.MANIFEST_NAME
            manifest.write_text(json.dumps({"kernel_release_version": "v0.8.0"}), encoding="utf-8")
            (artifacts / sidecar.MANIFEST_BUNDLE_NAME).write_text("producer", encoding="utf-8")
            (artifacts / f"{sidecar.MANIFEST_NAME}.kernel.cosign.bundle").write_text("kernel", encoding="utf-8")
            (artifacts / "ordinary-release-asset").write_text("asset", encoding="utf-8")
            (artifacts / "ordinary-release-asset.cosign.bundle").write_text("kernel", encoding="utf-8")
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_cosign = fake_bin / "cosign"
            fake_cosign.write_text(
                "#!/usr/bin/env bash\n"
                "case \" $* \" in\n"
                "  *\" --certificate-identity https://github.com/Mindburn-Labs/helm-ai-kernel/.github/workflows/release.yml@refs/tags/v0.8.0 \"*) exit 0 ;;\n"
                "  *\" --certificate-identity https://github.com/Mindburn-Labs/app-helm-console/.github/workflows/release-local-sidecar.yml@refs/tags/helm-console-sidecar-v0.8.0 \"*) exit 0 ;;\n"
                "  *) exit 23 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_cosign.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env["KERNEL_RELEASE_TAG"] = "v9.9.9"
            result = subprocess.run(
                ["make", "verify-cosign", f"COSIGN_ARTIFACT_DIR={artifacts}"],
                cwd=REPOSITORY_ROOT,
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("verified=3 failed=0", result.stdout)

    def test_kernel_cosign_verifier_rejects_console_contract_without_manifest_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / "artifacts"
            artifacts.mkdir()
            console_assets = artifacts / "nested-release-assets"
            console_assets.mkdir()
            (console_assets / sidecar.MANIFEST_NAME).write_text("{}", encoding="utf-8")
            (console_assets / sidecar.MANIFEST_BUNDLE_NAME).write_text("producer", encoding="utf-8")
            (console_assets / sidecar.KERNEL_MANIFEST_BUNDLE_NAME).write_text("kernel", encoding="utf-8")
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_cosign = fake_bin / "cosign"
            fake_cosign.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            fake_cosign.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env.pop("KERNEL_RELEASE_TAG", None)
            result = subprocess.run(
                ["bash", str(REPOSITORY_ROOT / "scripts/release/verify_cosign.sh"), str(artifacts)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires an exact Kernel tag in the Console manifest", result.stdout)

    def test_kernel_cosign_verifier_requires_both_manifest_bundles_for_a_tag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory) / "artifacts"
            artifacts.mkdir()
            (artifacts / sidecar.MANIFEST_NAME).write_text(json.dumps({"kernel_release_version": "v0.8.0"}), encoding="utf-8")
            (artifacts / f"{sidecar.MANIFEST_NAME}.kernel.cosign.bundle").write_text("kernel", encoding="utf-8")
            fake_bin = Path(directory) / "bin"
            fake_bin.mkdir()
            fake_cosign = fake_bin / "cosign"
            fake_cosign.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            fake_cosign.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}:{env['PATH']}"
            env.pop("KERNEL_RELEASE_TAG", None)
            result = subprocess.run(
                ["bash", str(REPOSITORY_ROOT / "scripts/release/verify_cosign.sh"), str(artifacts)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requires exactly one Console manifest plus both producer and Kernel bundles", result.stdout)


if __name__ == "__main__":
    unittest.main()
