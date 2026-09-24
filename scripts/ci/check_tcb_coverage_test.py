#!/usr/bin/env python3
"""Known-good and known-bad inputs for the TCB coverage gate."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from check_tcb_coverage import (  # noqa: E402
    MODULE_PREFIX,
    CoverageError,
    check,
    parse_floors,
    parse_profile,
)

SCRIPT = pathlib.Path(__file__).resolve().parent / "check_tcb_coverage.py"
FLOORS = "default 85\ncrypto\nexecutor 60  # frozen\n"


def block(package: str, line: int, statements: int, count: int) -> str:
    return f"{MODULE_PREFIX}{package}/file.go:{line}.1,{line + 1}.2 {statements} {count}\n"


def profile(crypto: tuple[int, int], executor: tuple[int, int] | None = (7, 10)) -> str:
    """Build a profile where each package has `covered` of `total` statements."""
    text = "mode: atomic\n"
    for package, counts in (("crypto", crypto), ("executor", executor)):
        if counts is None:
            continue
        covered, total = counts
        text += block(package, 1, covered, 1) + block(package, 10, total - covered, 0)
    return text


class TcbCoverageGateTest(unittest.TestCase):
    def run_check(self, text: str, floors: str = FLOORS) -> list[str]:
        return check(parse_profile(text), parse_floors(floors))

    def test_packages_at_their_floors_pass(self) -> None:
        report = self.run_check(profile(crypto=(85, 100), executor=(60, 100)))
        self.assertTrue(any(line.strip().startswith("crypto") for line in report))

    def test_package_below_default_fails(self) -> None:
        with self.assertRaisesRegex(CoverageError, "crypto: 84.00% is below its floor of 85.00%"):
            self.run_check(profile(crypto=(84, 100)))

    def test_package_below_its_frozen_floor_fails(self) -> None:
        with self.assertRaisesRegex(CoverageError, "executor: 59.00% is below its floor of 60.00%"):
            self.run_check(profile(crypto=(90, 100), executor=(59, 100)))

    def test_unmeasured_package_fails(self) -> None:
        # A package dropped from the test run must not read as "no regression".
        with self.assertRaisesRegex(CoverageError, "executor: no statements measured"):
            self.run_check(profile(crypto=(90, 100), executor=None))

    def test_empty_profile_fails(self) -> None:
        for text in ("", "mode: atomic\n", "not a profile\n"):
            with self.subTest(text=text), self.assertRaises(CoverageError):
                parse_profile(text)

    def test_exception_that_reached_the_default_must_be_removed(self) -> None:
        with self.assertRaisesRegex(CoverageError, "executor: .* remove its own floor"):
            self.run_check(profile(crypto=(90, 100), executor=(86, 100)))

    def test_repeated_blocks_count_once(self) -> None:
        # The same block instrumented by two test binaries; covered by one.
        location = f"{MODULE_PREFIX}crypto/file.go:1.1,2.2"
        text = f"mode: atomic\n{location} 10 0\n{location} 10 3\n" + block("executor", 1, 10, 1)
        self.assertEqual(parse_profile(text)[MODULE_PREFIX + "crypto"], (10, 10))

    def test_floors_file_must_be_well_formed(self) -> None:
        for bad in ("crypto\n", "default 85\n", "default 85\ncrypto 90\n", "default 85\ncrypto\ncrypto\n"):
            with self.subTest(floors=bad), self.assertRaises(CoverageError):
                parse_floors(bad)

    def test_committed_floors_file_parses(self) -> None:
        floors = parse_floors((SCRIPT.parent / "tcb-coverage-floors.txt").read_text(encoding="utf-8"))
        self.assertEqual(floors.default, 85)
        self.assertIn("crypto", floors.packages)

    def test_command_line_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            floors = pathlib.Path(tmp, "floors.txt")
            floors.write_text(FLOORS, encoding="utf-8")
            good = pathlib.Path(tmp, "good.out")
            good.write_text(profile(crypto=(85, 100), executor=(60, 100)), encoding="utf-8")
            bad = pathlib.Path(tmp, "bad.out")
            bad.write_text(profile(crypto=(10, 100)), encoding="utf-8")
            run = lambda *args: subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True)  # noqa: E731
            self.assertEqual(run("check", str(good), str(floors)).returncode, 0)
            failed = run("check", str(bad), str(floors))
            self.assertEqual(failed.returncode, 1)
            self.assertIn("TCB coverage gate failed", failed.stderr)
            self.assertEqual(run("packages", str(floors)).stdout.split(), ["./pkg/crypto", "./pkg/executor"])


if __name__ == "__main__":
    unittest.main()
