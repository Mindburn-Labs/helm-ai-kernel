#!/usr/bin/env python3
"""Self-test for check_receipt_verify_assets.py.

The checker is the release gate for the standalone receipt_verify assets, so
this test drives it against a real host build and against planted defects: a
missing asset, an empty one, a wrong executable header, a binary that exits 0
for everything and a binary that prints a constant verdict. Each must fail.

quantum_posture: these tests exercise a classical Ed25519 verifier build on a
frozen fixture; they implement no cryptographic control and make no
post-quantum claim.
"""
from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "release" / "check_receipt_verify_assets.py"

spec = importlib.util.spec_from_file_location("check_receipt_verify_assets", CHECKER)
assert spec is not None and spec.loader is not None
checker = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = checker
spec.loader.exec_module(checker)

HOST = checker.host_asset_name(platform.system(), platform.machine())
POSIX_HOST = HOST is not None and not HOST.endswith(".exe")


def stub_binary(name: str) -> bytes:
    """A file that carries the right executable header and nothing else."""
    return checker.MAGIC[checker.asset_platform(name)] + b"\x00" * 64


class AssetNames(unittest.TestCase):
    def test_host_asset_mapping(self) -> None:
        self.assertEqual(checker.host_asset_name("Linux", "x86_64"), "receipt_verify-linux-amd64")
        self.assertEqual(checker.host_asset_name("Linux", "aarch64"), "receipt_verify-linux-arm64")
        self.assertEqual(checker.host_asset_name("Darwin", "arm64"), "receipt_verify-darwin-arm64")
        self.assertEqual(checker.host_asset_name("Darwin", "x86_64"), "receipt_verify-darwin-amd64")
        self.assertEqual(checker.host_asset_name("Windows", "AMD64"), "receipt_verify-windows-amd64.exe")
        self.assertIsNone(checker.host_asset_name("Windows", "arm64"))
        self.assertIsNone(checker.host_asset_name("Linux", "riscv64"))
        self.assertIsNone(checker.host_asset_name("FreeBSD", "amd64"))

    def test_every_asset_has_a_known_platform_header(self) -> None:
        for name in checker.ASSETS:
            self.assertIn(checker.asset_platform(name), checker.MAGIC, name)


@unittest.skipUnless(POSIX_HOST, "needs a POSIX host that has a receipt_verify asset")
class CheckAgainstHostBuild(unittest.TestCase):
    build_dir: tempfile.TemporaryDirectory[str]
    host_binary: Path

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("go") is None:
            raise unittest.SkipTest("go is required to build receipt_verify")
        cls.build_dir = tempfile.TemporaryDirectory(prefix="receipt-verify-build.")
        cls.host_binary = Path(cls.build_dir.name) / "receipt_verify"
        env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0"}
        subprocess.run(
            ["go", "build", "-o", str(cls.host_binary), "./cmd/receipt_verify/"],
            cwd=ROOT / "core",
            env=env,
            check=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.build_dir.cleanup()

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="receipt-verify-assets.")
        self.addCleanup(self._tmp.cleanup)
        self.assets = Path(self._tmp.name)
        for name in checker.ASSETS:
            target = self.assets / name
            if name == HOST:
                shutil.copy2(self.host_binary, target)
            else:
                target.write_bytes(stub_binary(name))
            target.chmod(0o755)

    def run_checker(self, **kwargs: object) -> list[str]:
        errors, _ = checker.check(self.assets, ROOT, **kwargs)  # type: ignore[arg-type]
        return errors

    def replace_host(self, body: str) -> None:
        path = self.assets / HOST
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)

    def test_complete_set_passes_and_says_what_ran(self) -> None:
        errors, summary = checker.check(self.assets, ROOT)
        self.assertEqual(errors, [])
        self.assertIn(HOST, summary)
        self.assertIn("rejected a wrong key and a tampered receipt", summary)

    def test_cli_exit_codes(self) -> None:
        def cli(directory: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, str(CHECKER), str(directory)], capture_output=True, text=True, check=False
            )

        ok = cli(self.assets)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("receipt_verify assets:", ok.stdout)

        victim = next(name for name in checker.ASSETS if name != HOST)
        (self.assets / victim).unlink()
        bad = cli(self.assets)
        self.assertEqual(bad.returncode, 1)
        self.assertIn(f"missing receipt_verify release asset: {victim}", bad.stderr)

        self.assertEqual(cli(self.assets / "does-not-exist").returncode, 1)

    def test_each_missing_asset_is_reported_by_name(self) -> None:
        for name in checker.ASSETS:
            with self.subTest(missing=name):
                path = self.assets / name
                data = path.read_bytes()
                path.unlink()
                try:
                    errors = self.run_checker()
                finally:
                    path.write_bytes(data)
                    path.chmod(0o755)
                self.assertTrue(any(name in error for error in errors), errors)

    def test_empty_asset_fails(self) -> None:
        other = next(name for name in checker.ASSETS if name != HOST)
        (self.assets / other).write_bytes(b"")
        errors = self.run_checker()
        self.assertTrue(any("empty" in error and other in error for error in errors), errors)

    def test_wrong_platform_header_fails(self) -> None:
        windows = "receipt_verify-windows-amd64.exe"
        (self.assets / windows).write_bytes(stub_binary("receipt_verify-linux-amd64"))
        errors = self.run_checker()
        self.assertTrue(any(windows in error and "executable header" in error for error in errors), errors)

    def test_binary_that_cannot_run_fails(self) -> None:
        magic = checker.MAGIC[checker.asset_platform(HOST)]
        (self.assets / HOST).write_bytes(magic + b"\x00" * 64)
        errors = self.run_checker()
        self.assertTrue(any("could not be executed" in error for error in errors), errors)

    def test_constant_verdict_binary_fails(self) -> None:
        """A stub that prints a valid verdict and exits 0 for any input is caught by the controls."""
        stub = self.assets / HOST
        stub.write_text('#!/bin/sh\necho \'{"valid": true, "receipts": 2}\'\nexit 0\n', encoding="utf-8")
        stub.chmod(0o755)
        # The stub has no platform header; call the behaviour check directly so
        # this case isolates the positive/negative controls.
        errors = checker._check_behaviour(stub, ROOT)
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any("wrong key" in error for error in errors), errors)
        self.assertTrue(any("tampered" in error for error in errors), errors)

    def test_binary_that_rejects_everything_fails(self) -> None:
        stub = self.assets / HOST
        stub.write_text('#!/bin/sh\necho \'{"valid": false, "receipts": 2}\'\nexit 1\n', encoding="utf-8")
        stub.chmod(0o755)
        errors = checker._check_behaviour(stub, ROOT)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("did not verify the frozen receipt chain", errors[0])

    def test_host_without_asset_needs_explicit_opt_in(self) -> None:
        errors, _ = checker.check(self.assets, ROOT, host=("Linux", "riscv64"))
        self.assertTrue(any("no receipt_verify asset runs on this host" in error for error in errors), errors)
        errors, summary = checker.check(self.assets, ROOT, allow_unexecuted=True, host=("Linux", "riscv64"))
        self.assertEqual(errors, [])
        self.assertIn("not executed", summary)


if __name__ == "__main__":
    unittest.main()
