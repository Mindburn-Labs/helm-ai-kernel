#!/usr/bin/env python3
"""Self-tests for the release preparation script."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import prepare_version

ROOT = prepare_version.ROOT


class RewriteSdkManifestsTests(unittest.TestCase):
    def test_rewrite_is_idempotent_on_a_current_tree(self) -> None:
        """On a tree whose manifests already match, a rewrite changes nothing.

        This is the property that makes it safe for prepare-version to always
        rewrite: when the generated sources moved (a version bump), the pins
        follow; when nothing moved, the write is byte-identical.
        """
        manifest_paths = sorted(ROOT.glob("sdk/*/generated.manifest.json"))
        self.assertGreaterEqual(len(manifest_paths), 5, "expected an SDK manifest per language")
        before = {path: path.read_bytes() for path in manifest_paths}

        rewritten = prepare_version.rewrite_sdk_manifests()

        self.assertEqual(sorted(rewritten), sorted(str(p.relative_to(ROOT)) for p in manifest_paths))
        for path in manifest_paths:
            self.assertEqual(before[path], path.read_bytes(), f"{path} changed on a current tree")

    def test_every_manifest_verifies_after_rewrite(self) -> None:
        for manifest_path in sorted(ROOT.glob("sdk/*/generated.manifest.json")):
            sdk_dir = manifest_path.parent.relative_to(ROOT)
            result = subprocess.run(
                ["python3", "scripts/sdk/manifest.py", "verify", str(sdk_dir)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, f"{sdk_dir}: {result.stdout}{result.stderr}")


class PublicDocsApiContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.manifest_path = self.root / "docs" / "public-docs.manifest.json"
        self.source_path = self.root / "api" / "openapi" / "helm.openapi.yaml"
        self.manifest_path.parent.mkdir(parents=True)
        self.source_path.parent.mkdir(parents=True)
        self.source_path.write_text("openapi: 3.1.0\ninfo:\n  version: 0.8.4\n", encoding="utf-8")
        self.write_manifest()
        root_patch = mock.patch.object(prepare_version, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        drift_root_patch = mock.patch.object(prepare_version.drift, "ROOT", self.root)
        drift_root_patch.start()
        self.addCleanup(drift_root_patch.stop)

    def write_manifest(self, api_contract: object = None) -> None:
        if api_contract is None:
            api_contract = {
                "schema_version": 1,
                "source_path": "api/openapi/helm.openapi.yaml",
                "content_sha256": "sha256:stale",
                "git_blob_sha1": "stale",
            }
        self.manifest_path.write_text(json.dumps({"api_contract": api_contract}) + "\n", encoding="utf-8")

    def test_refresh_updates_hashes_and_is_idempotent(self) -> None:
        self.assertTrue(prepare_version.refresh_public_docs_api_contract())
        contract = json.loads(self.manifest_path.read_text(encoding="utf-8"))["api_contract"]
        expected_digest = hashlib.sha256(self.source_path.read_bytes()).hexdigest()
        expected_blob = subprocess.run(
            ["git", "hash-object", "api/openapi/helm.openapi.yaml"],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(contract["content_sha256"], f"sha256:{expected_digest}")
        self.assertEqual(contract["git_blob_sha1"], expected_blob)
        before = self.manifest_path.read_bytes()
        self.assertFalse(prepare_version.refresh_public_docs_api_contract())
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_missing_or_non_file_manifest_fails_closed(self) -> None:
        self.manifest_path.unlink()
        with self.assertRaisesRegex(SystemExit, "required public docs manifest"):
            prepare_version.refresh_public_docs_api_contract()

    def test_malformed_manifest_fails_closed(self) -> None:
        for malformed in ("not JSON", "[]"):
            with self.subTest(manifest=malformed):
                self.manifest_path.write_text(malformed, encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "required public docs manifest"):
                    prepare_version.refresh_public_docs_api_contract()

    def test_missing_or_malformed_api_contract_fails_closed(self) -> None:
        for api_contract in ([], "not an object"):
            with self.subTest(api_contract=api_contract):
                self.write_manifest(api_contract)
                with self.assertRaisesRegex(SystemExit, "api_contract must be a JSON object"):
                    prepare_version.refresh_public_docs_api_contract()
        self.manifest_path.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "api_contract must be a JSON object"):
            prepare_version.refresh_public_docs_api_contract()

    def test_source_path_must_be_exact(self) -> None:
        for source_path in (None, "api/openapi/other.yaml", "/tmp/helm.openapi.yaml"):
            with self.subTest(source_path=source_path):
                self.write_manifest({"source_path": source_path})
                with self.assertRaisesRegex(SystemExit, "api_contract.source_path must be"):
                    prepare_version.refresh_public_docs_api_contract()

    def test_missing_source_file_fails_closed(self) -> None:
        self.source_path.unlink()
        with self.assertRaisesRegex(SystemExit, "required public docs API contract"):
            prepare_version.refresh_public_docs_api_contract()


class BoundaryManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.generator = self.root / "tools" / "boundary" / "generate-manifest.sh"
        self.manifest = self.root / "tools" / "boundary" / "protected.manifest"
        self.generator.parent.mkdir(parents=True)
        self.generator.write_text(
            "#!/bin/sh\nset -eu\nprintf 'generated manifest\\n' > tools/boundary/protected.manifest\n",
            encoding="utf-8",
        )
        self.generator.chmod(0o755)
        self.manifest.write_text("stale manifest\n", encoding="utf-8")
        root_patch = mock.patch.object(prepare_version, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        drift_root_patch = mock.patch.object(prepare_version.drift, "ROOT", self.root)
        drift_root_patch.start()
        self.addCleanup(drift_root_patch.stop)

    def test_refresh_updates_manifest_and_is_idempotent(self) -> None:
        self.assertTrue(prepare_version.refresh_boundary_manifest())
        self.assertEqual(self.manifest.read_text(encoding="utf-8"), "generated manifest\n")
        before = self.manifest.read_bytes()
        self.assertFalse(prepare_version.refresh_boundary_manifest())
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_missing_generator_fails_closed(self) -> None:
        self.generator.unlink()
        with self.assertRaisesRegex(SystemExit, "required boundary manifest generator"):
            prepare_version.refresh_boundary_manifest()

    def test_missing_manifest_fails_closed(self) -> None:
        self.manifest.unlink()
        with self.assertRaisesRegex(SystemExit, "required boundary manifest is missing"):
            prepare_version.refresh_boundary_manifest()

    def test_generator_failure_propagates(self) -> None:
        self.generator.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
        with self.assertRaises(subprocess.CalledProcessError):
            prepare_version.refresh_boundary_manifest()


class MainOrderTests(unittest.TestCase):
    def test_derived_manifests_refresh_before_drift_check(self) -> None:
        events: list[str] = []

        def record_run(command: list[str]) -> None:
            events.append("run:" + " ".join(command))

        with (
            mock.patch.object(
                prepare_version,
                "parse_args",
                return_value=prepare_version.argparse.Namespace(
                    version="0.8.4", contract=Path("contract.json"), force=False
                ),
            ),
            mock.patch.object(prepare_version.drift, "load_contract", return_value={"normalization_enabled": True}),
            mock.patch.object(prepare_version, "rewrite_sdk_manifests", return_value=[]),
            mock.patch.object(
                prepare_version,
                "refresh_public_docs_api_contract",
                side_effect=lambda: events.append("public-docs") or False,
            ),
            mock.patch.object(
                prepare_version,
                "refresh_boundary_manifest",
                side_effect=lambda: events.append("boundary") or False,
            ),
            mock.patch.object(
                prepare_version,
                "warn_missing_console_pin",
                side_effect=lambda _version: events.append("console-pin"),
            ),
            mock.patch.object(prepare_version, "run", side_effect=record_run),
        ):
            self.assertEqual(prepare_version.main(), 0)

        self.assertEqual(
            events,
            [
                "public-docs",
                "boundary",
                "console-pin",
                "run:python3 scripts/release/check_version_drift.py --expected-version 0.8.4 local",
            ],
        )


class ConsolePinWarningTests(unittest.TestCase):
    def test_missing_row_is_named_with_the_consequence(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            prepare_version.warn_missing_console_pin("999.999.999")
        message = stdout.getvalue()
        self.assertIn("v999.999.999", message)
        self.assertIn("console-local-sidecar-pins.json", message)
        self.assertIn("stranded", message)

    def test_present_row_stays_silent(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        pins = json.loads((ROOT / "release" / "console-local-sidecar-pins.json").read_text(encoding="utf-8"))
        if not any(p.get("kernel_release_version") == f"v{version}" for p in pins.get("pins", [])):
            self.skipTest(f"no pin row for v{version} on this tree; the warning is expected here")
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            prepare_version.warn_missing_console_pin(version)
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
