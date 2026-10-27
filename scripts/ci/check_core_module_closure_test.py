#!/usr/bin/env python3
"""Negative controls for isolation of the native cold module resolution gate."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("closure", Path(__file__).with_name("check_core_module_closure.py"))
closure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(closure)


class ColdModuleClosureTests(unittest.TestCase):
    def run_guard(self, *, replacement=None, version="v0.11.2", downloaded_version=None, reuse=False, escape=False, selected_version=None, mutate=False):
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            core = Path(temporary)
            (core / "go.mod").write_text("module " + closure.CORE_MODULE + "\n")
            (core / "go.sum").write_text("locked checksums\n")

            def output(command, *, cwd, env, text):
                self.assertEqual(env["GOWORK"], "off")
                self.assertEqual(env["GOFLAGS"], "-mod=readonly")
                self.assertEqual(env["GONOPROXY"], closure.PRIVATE_PATTERN)
                self.assertEqual(env["GONOSUMDB"], "checksum-policy-preserved")
                self.assertNotEqual(env["GOMODCACHE"], "/inherited/warm/cache")
                self.assertNotEqual(cwd, core)
                calls.append(command)
                if command[1:3] == ["mod", "edit"]:
                    self.assertEqual(list(Path(env["GOMODCACHE"]).iterdir()), [])
                    return json.dumps({"Module": {"Path": closure.CORE_MODULE}, "Require": [{"Path": closure.SDK_MODULE, "Version": version}], "Replace": replacement})
                if command[1:3] == ["mod", "download"]:
                    self.assertEqual(env["GOPROXY"], "direct")
                    if version == "unreachable-pseudo-version":
                        raise subprocess.CalledProcessError(1, command, stderr="unknown revision")
                    return json.dumps({"Path": closure.SDK_MODULE, "Version": downloaded_version or version, "Dir": "/inherited/warm/cache/sdk" if escape else str(Path(env["GOMODCACHE"]) / "sdk"), "Origin": {"Hash": "canonical-source"}, "Sum": "h1:locked-source", "GoModSum": "h1:locked-module", "Reuse": reuse})
                return json.dumps({"Path": closure.SDK_MODULE, "Version": selected_version or version})

            def run(command, *, cwd, env, check):
                self.assertEqual(command, ["go", "mod", "download"])
                self.assertEqual(env["GOWORK"], "off")
                self.assertEqual(env["GONOPROXY"], closure.PRIVATE_PATTERN)
                calls.append(command)
                if mutate:
                    (cwd / "go.sum").write_text("unexpected repair\n")

            with patch.dict(os.environ, {"GOWORK": "/inherited/go.work", "GOMODCACHE": "/inherited/warm/cache", "GOFLAGS": "-mod=mod", "GOPROXY": "https://public-proxy.invalid", "GONOPROXY": "none", "GONOSUMDB": "checksum-policy-preserved"}), patch.object(closure.subprocess, "check_output", side_effect=output), patch.object(closure.subprocess, "run", side_effect=run):
                closure.check_closure(core)
            self.assertIn(["go", "mod", "download", "-json", closure.SDK_MODULE + "@" + version], calls)
            self.assertIn(["go", "mod", "download"], calls)

    def test_overrides_workspace_and_warm_cache_then_downloads_full_closure(self):
        self.run_guard()

    def test_unreachable_declared_pin_cannot_use_proxy_or_continue(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_guard(version="unreachable-pseudo-version")

    def test_first_party_replace_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "replacement"):
            self.run_guard(replacement=[{"Old": {"Path": closure.SDK_MODULE}, "New": {"Path": closure.SDK_MODULE, "Version": "v9.9.9"}}])

    def test_local_replace_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "replacement"):
            self.run_guard(replacement=[{"Old": {"Path": "example.com/dependency"}, "New": {"Path": "../workspace"}}])

    def test_reused_download_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "freshly"):
            self.run_guard(reuse=True)

    def test_inherited_cache_escape_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "fresh module cache"):
            self.run_guard(escape=True)

    def test_download_version_substitution_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "requirement"):
            self.run_guard(downloaded_version="v9.9.9")

    def test_graph_version_substitution_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "substituted"):
            self.run_guard(selected_version="v9.9.9")

    def test_lockfile_mutation_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "changed go.sum"):
            self.run_guard(mutate=True)

    def test_gate_blocks_source_and_release_profiles(self):
        registry = json.loads((closure.ROOT / "scripts/ci/quality-gates.json").read_text())
        gate = next(g for g in registry["gates"] if g["id"] == "core-module-closure")
        self.assertFalse(gate.get("advisory", False))
        self.assertEqual(gate["command"], "make test-core-module-closure")
        for profile in ("pr", "merge", "release"):
            self.assertIn(gate["id"], registry["profiles"][profile]["gates"])


if __name__ == "__main__":
    unittest.main()
