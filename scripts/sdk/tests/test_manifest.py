#!/usr/bin/env python3
"""Unit tests for scripts/sdk/manifest.py (HELM-W3).

Runs with the stdlib only so the gate works in minimal CI images:

    python3 -m unittest discover -s scripts/sdk/tests -v
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

MANIFEST_PY = Path(__file__).resolve().parents[1] / "manifest.py"

spec = importlib.util.spec_from_file_location("sdk_manifest", MANIFEST_PY)
manifest = importlib.util.module_from_spec(spec)
sys.modules.setdefault("sdk_manifest", manifest)
spec.loader.exec_module(manifest)


class ManifestTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.sdk_dir = self.root / "sdk" / "ts"
        self.sdk_dir.mkdir(parents=True)
        self.spec_path = self.root / "api" / "openapi" / "helm.openapi.yaml"
        self.spec_path.parent.mkdir(parents=True)
        self.spec_path.write_text("openapi: 3.1.0\n", encoding="utf-8")
        self.gen_file = self.sdk_dir / "src" / "types.gen.ts"
        self.gen_file.parent.mkdir(parents=True)
        self.gen_file.write_text("export type A = string;\n", encoding="utf-8")
        self.image = "openapitools/openapi-generator-cli:v7.4.0@sha256:deadbeef"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write(self) -> Path:
        return manifest.write_manifest(self.sdk_dir, self.image, self.spec_path, ["src/types.gen.ts"])

    def test_write_then_verify_passes(self) -> None:
        out = self._write()
        self.assertTrue(out.is_file())
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["sdk"], "ts")
        self.assertEqual(data["generator"], self.image)
        self.assertEqual(data["files"][0]["path"], "src/types.gen.ts")
        self.assertEqual(manifest.verify_manifest(self.sdk_dir), [])

    def test_write_is_deterministic(self) -> None:
        first = self._write().read_text(encoding="utf-8")
        second = self._write().read_text(encoding="utf-8")
        self.assertEqual(first, second)

    def test_verify_fails_closed_without_manifest(self) -> None:
        problems = manifest.verify_manifest(self.sdk_dir)
        self.assertTrue(any("missing manifest" in p for p in problems))

    def test_verify_detects_file_mutation(self) -> None:
        self._write()
        self.gen_file.write_text("export type A = number;\n", encoding="utf-8")
        problems = manifest.verify_manifest(self.sdk_dir)
        self.assertTrue(any("hash mismatch" in p for p in problems))

    def test_verify_detects_missing_file(self) -> None:
        self._write()
        self.gen_file.unlink()
        problems = manifest.verify_manifest(self.sdk_dir)
        self.assertTrue(any("missing on disk" in p for p in problems))

    def test_verify_detects_manifest_tampering(self) -> None:
        out = self._write()
        data = json.loads(out.read_text(encoding="utf-8"))
        data["files"][0]["sha256"] = "0" * 64
        out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        problems = manifest.verify_manifest(self.sdk_dir)
        self.assertTrue(any("hash mismatch" in p for p in problems))

    def test_verify_rejects_unparseable_manifest(self) -> None:
        (self.sdk_dir / manifest.MANIFEST_NAME).write_text("{not json", encoding="utf-8")
        problems = manifest.verify_manifest(self.sdk_dir)
        self.assertTrue(any("unparseable" in p for p in problems))

    def test_write_refuses_missing_generated_file(self) -> None:
        with self.assertRaises(SystemExit):
            manifest.write_manifest(self.sdk_dir, self.image, self.spec_path, ["src/nope.ts"])

    def test_cli_verify_exit_codes(self) -> None:
        self._write()
        self.assertEqual(manifest.main(["manifest.py", "verify", str(self.sdk_dir)]), 0)
        self.gen_file.write_text("drifted\n", encoding="utf-8")
        self.assertEqual(manifest.main(["manifest.py", "verify", str(self.sdk_dir)]), 1)


if __name__ == "__main__":
    unittest.main()
