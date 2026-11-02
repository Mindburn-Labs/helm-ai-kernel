#!/usr/bin/env python3
"""Self-test for check_receipt_verify_assets.py.

The checker is the release gate for the standalone receipt_verify assets, so
this test drives it against real Go builds for all five targets and against
planted defects: a missing asset, an empty or tiny one, a wrong executable
format, a binary whose architecture does not match its name, a binary that exits
0 for everything, one that prints a constant verdict and one that hangs. Each
must fail.

Skips are loud. When CI is set, a missing Go toolchain or a host without a POSIX
receipt_verify asset fails the run instead of skipping it, because a skipped
self-test would read as a pass.

quantum_posture: these tests exercise a classical Ed25519 verifier build on a
frozen fixture; they implement no cryptographic control and make no
post-quantum claim.
"""
from __future__ import annotations

import importlib.util
import os
import platform
import shutil
import struct
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
POSIX_HOST = os.name == "posix" and HOST is not None and not HOST.endswith(".exe")


def skip_or_fail(reason: str) -> None:
    """Skip loudly on a workstation; fail under CI, where a skip would read as a pass."""
    if os.environ.get("CI"):
        raise AssertionError(f"{reason}; CI is set, so this is a failure, not a skip")
    print(f"WARNING: skipping receipt_verify self-tests: {reason}", file=sys.stderr)
    raise unittest.SkipTest(reason)


def stub_binary(goos: str, goarch: str, size: int = checker.MIN_ASSET_BYTES) -> bytes:
    """A file of the given size carrying a minimal executable header for goos/goarch."""
    if goos == "linux":
        machine = {v: k for k, v in checker.ELF_MACHINE.items()}[goarch]
        head = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9 + struct.pack("<HH", 2, machine)
    elif goos == "darwin":
        cputype = {v: k for k, v in checker.MACHO_CPUTYPE.items()}[goarch]
        head = b"\xcf\xfa\xed\xfe" + struct.pack("<I", cputype)
    elif goos == "windows":
        machine = {v: k for k, v in checker.PE_MACHINE.items()}[goarch]
        head = b"MZ" + b"\x00" * (0x3C - 2) + struct.pack("<I", 0x80)
        head += b"\x00" * (0x80 - len(head)) + b"PE\x00\x00" + struct.pack("<H", machine)
    else:
        raise ValueError(goos)
    return head + b"\x00" * (size - len(head))


def stub_set(directory: Path) -> None:
    for name in checker.ASSETS:
        target = directory / name
        target.write_bytes(stub_binary(*checker.asset_target(name)))
        target.chmod(0o755)


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

    def test_asset_target_parses_every_name(self) -> None:
        self.assertEqual(checker.asset_target("receipt_verify-linux-arm64"), ("linux", "arm64"))
        self.assertEqual(checker.asset_target("receipt_verify-windows-amd64.exe"), ("windows", "amd64"))
        for name in checker.ASSETS:
            goos, _ = checker.asset_target(name)
            self.assertIn(goos, checker.FORMAT_OS.values(), name)


class HeaderChecks(unittest.TestCase):
    """Size and header checks on the four assets the host cannot execute."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="receipt-verify-headers.")
        self.addCleanup(self._tmp.cleanup)
        self.assets = Path(self._tmp.name)
        stub_set(self.assets)

    def test_matching_headers_pass(self) -> None:
        self.assertEqual(checker._check_presence(self.assets), [])

    def test_each_target_header_is_recognised(self) -> None:
        for name in checker.ASSETS:
            with self.subTest(name=name):
                head = (self.assets / name).read_bytes()[: checker.HEADER_BYTES]
                self.assertEqual(checker.executable_target(head), checker.asset_target(name))

    def test_amd64_binary_named_arm64_fails(self) -> None:
        for goos in ("linux", "darwin"):
            with self.subTest(goos=goos):
                name = f"receipt_verify-{goos}-arm64"
                (self.assets / name).write_bytes(stub_binary(goos, "amd64"))
                errors = checker._check_presence(self.assets)
                self.assertTrue(
                    any(name in e and f"{goos}/amd64 executable" in e and f"says {goos}/arm64" in e for e in errors),
                    errors,
                )
                (self.assets / name).write_bytes(stub_binary(goos, "arm64"))

    def test_arm64_pe_named_amd64_fails(self) -> None:
        name = "receipt_verify-windows-amd64.exe"
        (self.assets / name).write_bytes(stub_binary("windows", "arm64"))
        errors = checker._check_presence(self.assets)
        self.assertTrue(any(name in e and "windows/arm64 executable" in e for e in errors), errors)

    def test_wrong_executable_format_fails(self) -> None:
        name = "receipt_verify-windows-amd64.exe"
        (self.assets / name).write_bytes(stub_binary("linux", "amd64"))
        errors = checker._check_presence(self.assets)
        self.assertTrue(any(name in e and "linux/amd64 executable" in e and "says windows/amd64" in e for e in errors), errors)

    def test_file_without_executable_header_fails(self) -> None:
        name = "receipt_verify-darwin-amd64"
        (self.assets / name).write_bytes(b"#!/bin/sh\n" + b"\x00" * checker.MIN_ASSET_BYTES)
        errors = checker._check_presence(self.assets)
        self.assertTrue(any(name in e and "no ELF, Mach-O or PE header" in e for e in errors), errors)

    def test_mz_stub_without_pe_signature_fails(self) -> None:
        name = "receipt_verify-windows-amd64.exe"
        (self.assets / name).write_bytes(b"MZ" + b"\x00" * checker.MIN_ASSET_BYTES)
        errors = checker._check_presence(self.assets)
        self.assertTrue(any(name in e and "without a PE signature" in e for e in errors), errors)

    def test_tiny_file_with_a_valid_header_fails(self) -> None:
        name = "receipt_verify-linux-arm64"
        (self.assets / name).write_bytes(stub_binary("linux", "arm64", size=4096))
        errors = checker._check_presence(self.assets)
        self.assertTrue(any(name in e and "smaller than" in e for e in errors), errors)

    def test_empty_asset_fails(self) -> None:
        name = "receipt_verify-darwin-arm64"
        (self.assets / name).write_bytes(b"")
        errors = checker._check_presence(self.assets)
        self.assertTrue(any("empty" in e and name in e for e in errors), errors)

    def test_each_missing_asset_is_reported_by_name(self) -> None:
        for name in checker.ASSETS:
            with self.subTest(missing=name):
                path = self.assets / name
                data = path.read_bytes()
                path.unlink()
                try:
                    errors = checker._check_presence(self.assets)
                finally:
                    path.write_bytes(data)
                self.assertTrue(any(f"missing receipt_verify release asset: {name}" == e for e in errors), errors)

    def test_host_without_asset_needs_explicit_opt_in_and_says_nothing_ran(self) -> None:
        errors, _ = checker.check(self.assets, ROOT, host=("Linux", "riscv64"))
        self.assertTrue(any("no receipt_verify asset runs on this host" in e for e in errors), errors)
        errors, summary = checker.check(self.assets, ROOT, allow_unexecuted=True, host=("Linux", "riscv64"))
        self.assertEqual(errors, [])
        self.assertIn("none executed", summary)
        header_part = summary.split("header-checked only, not executed: ", 1)[1]
        for name in checker.ASSETS:
            self.assertIn(name, header_part)


class BehaviourAgainstStubs(unittest.TestCase):
    """The positive check and both controls, against POSIX shell stubs."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.name != "posix":
            skip_or_fail("the behaviour stubs are POSIX shell scripts")

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="receipt-verify-stub.")
        self.addCleanup(self._tmp.cleanup)
        self.stub = Path(self._tmp.name) / "receipt_verify"

    def write_stub(self, body: str) -> None:
        self.stub.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        self.stub.chmod(0o755)

    def test_constant_verdict_binary_fails(self) -> None:
        """A stub that prints a valid verdict and exits 0 for any input is caught by the controls."""
        self.write_stub('echo \'{"valid": true, "receipts": 2}\'\nexit 0\n')
        errors = checker._check_behaviour(self.stub, ROOT)
        self.assertEqual(len(errors), 2, errors)
        self.assertTrue(any("wrong key" in e for e in errors), errors)
        self.assertTrue(any("tampered" in e for e in errors), errors)

    def test_binary_that_rejects_everything_fails(self) -> None:
        self.write_stub('echo \'{"valid": false, "receipts": 2}\'\nexit 1\n')
        errors = checker._check_behaviour(self.stub, ROOT)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("did not verify the frozen receipt chain", errors[0])

    def test_hang_is_reported_not_raised(self) -> None:
        self.write_stub("exec sleep 30\n")
        saved = checker.RUN_TIMEOUT_SECONDS
        checker.RUN_TIMEOUT_SECONDS = 1
        try:
            errors = checker._check_behaviour(self.stub, ROOT)
        finally:
            checker.RUN_TIMEOUT_SECONDS = saved
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("did not finish within 1s (frozen chain, own key)", errors[0])

    def test_hang_in_a_control_is_reported_not_raised(self) -> None:
        """Accept the real key, hang on anything else: the wrong-key control times out."""
        key = checker.json.loads((ROOT / checker.FIXTURE).read_text(encoding="utf-8"))["public_key_hex"]
        self.write_stub(
            'case "$*" in\n'
            f'  *"--key {key} "*) echo \'{{"valid": true, "receipts": 2}}\'; exit 0 ;;\n'
            "esac\n"
            "exec sleep 30\n"
        )
        # Headroom for the accepted run: macOS scans a fresh executable on its
        # first exec, which can take over a second.
        saved = checker.RUN_TIMEOUT_SECONDS
        checker.RUN_TIMEOUT_SECONDS = 5
        try:
            errors = checker._check_behaviour(self.stub, ROOT)
        finally:
            checker.RUN_TIMEOUT_SECONDS = saved
        self.assertEqual(errors, [f"{self.stub.name} did not finish within 5s (wrong-key control)"])


class CheckAgainstRealBuilds(unittest.TestCase):
    """The full check against real Go builds of all five targets."""

    build_dir: tempfile.TemporaryDirectory[str]

    @classmethod
    def setUpClass(cls) -> None:
        if not POSIX_HOST:
            skip_or_fail(f"no POSIX receipt_verify asset runs on {platform.system()}/{platform.machine()}")
        if shutil.which("go") is None:
            skip_or_fail("go is required to build receipt_verify")
        cls.build_dir = tempfile.TemporaryDirectory(prefix="receipt-verify-build.")
        for name in checker.ASSETS:
            goos, goarch = checker.asset_target(name)
            env = {**os.environ, "GOWORK": "off", "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch}
            subprocess.run(
                ["go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", str(Path(cls.build_dir.name) / name), "./cmd/receipt_verify/"],
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
            shutil.copy2(Path(self.build_dir.name) / name, self.assets / name)

    def test_complete_set_passes_and_says_what_ran(self) -> None:
        errors, summary = checker.check(self.assets, ROOT)
        self.assertEqual(errors, [])
        self.assertIn(f"executed {HOST}, which verified the frozen chain", summary)
        self.assertIn("rejected a wrong key and a tampered receipt", summary)
        header_part = summary.split("header-checked only, not executed: ", 1)[1]
        for name in checker.ASSETS:
            if name == HOST:
                self.assertNotIn(name, header_part)
            else:
                self.assertIn(name, header_part)

    def test_cli_exit_codes(self) -> None:
        def cli(directory: Path) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [sys.executable, str(CHECKER), str(directory)], capture_output=True, text=True, check=False
            )

        ok = cli(self.assets)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("receipt_verify assets:", ok.stdout)
        self.assertIn(f"executed {HOST}", ok.stdout)

        victim = next(name for name in checker.ASSETS if name != HOST)
        (self.assets / victim).unlink()
        bad = cli(self.assets)
        self.assertEqual(bad.returncode, 1)
        self.assertIn(f"missing receipt_verify release asset: {victim}", bad.stderr)

        self.assertEqual(cli(self.assets / "does-not-exist").returncode, 1)

    def test_real_build_under_another_name_fails(self) -> None:
        """A genuine verifier build staged under the wrong platform name is caught by its header."""
        for name in checker.ASSETS:
            if name == HOST:
                continue
            goos, goarch = checker.asset_target(name)
            twin = next(
                (other for other in checker.ASSETS if other != name and checker.asset_target(other)[0] == goos),
                None,
            )
            if twin is None:
                continue
            with self.subTest(name=name, staged_from=twin):
                original = (self.assets / name).read_bytes()
                shutil.copy2(self.assets / twin, self.assets / name)
                try:
                    errors = checker._check_presence(self.assets)
                finally:
                    (self.assets / name).write_bytes(original)
                self.assertTrue(any(name in e and f"says {goos}/{goarch}" in e for e in errors), errors)

    def test_host_binary_that_cannot_run_fails(self) -> None:
        goos, goarch = checker.asset_target(HOST)
        (self.assets / HOST).write_bytes(stub_binary(goos, goarch))
        (self.assets / HOST).chmod(0o755)
        errors = checker.check(self.assets, ROOT)[0]
        self.assertTrue(errors, "a header-only stub must not pass the behaviour check")
        self.assertTrue(all(HOST in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
