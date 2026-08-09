#!/usr/bin/env python3
"""Self-tests for the release preparation script."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import unittest
from pathlib import Path

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
