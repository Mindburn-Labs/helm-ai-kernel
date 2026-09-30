#!/usr/bin/env python3
"""Known-good and known-bad inputs for the Postgres proof gate."""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from check_postgres_proofs import discover, parse_manifest, verify  # noqa: E402

MANIFEST = parse_manifest("pkg/a TestA 2 race\npkg/b TestB 1 plain\n")


def log(*lines: str) -> str:
    return "".join(f"{line}\n" for line in lines)


class VerifyTest(unittest.TestCase):
    def test_every_run_passed(self) -> None:
        self.assertEqual(verify(MANIFEST, log("--- PASS: TestA (0.1s)", "--- PASS: TestA (0.1s)", "--- PASS: TestB (0.2s)")), [])

    def test_skip_is_a_failure(self) -> None:
        # What every one of these proofs does when HELM_TEST_POSTGRES_URL is unset.
        problems = verify(MANIFEST, log("--- SKIP: TestA (0.0s)", "--- SKIP: TestA (0.0s)", "--- PASS: TestB (0.2s)"))
        self.assertTrue(any("skipped" in p for p in problems), problems)

    def test_missing_test_is_a_failure(self) -> None:
        problems = verify(MANIFEST, log("--- PASS: TestA (0.1s)", "--- PASS: TestA (0.1s)"))
        self.assertEqual(problems, ["pkg/b TestB: passed 0 of 1 run(s)"])

    def test_short_count_is_a_failure(self) -> None:
        problems = verify(MANIFEST, log("--- PASS: TestA (0.1s)", "--- PASS: TestB (0.2s)"))
        self.assertEqual(problems, ["pkg/a TestA: passed 1 of 2 run(s)"])

    def test_subtest_passes_are_not_runs(self) -> None:
        problems = verify(MANIFEST, log("    --- PASS: TestA/x (0.0s)", "    --- PASS: TestA/y (0.0s)", "--- PASS: TestA (0.1s)", "--- PASS: TestB (0.2s)"))
        self.assertEqual(problems, ["pkg/a TestA: passed 1 of 2 run(s)"])

    def test_subtest_failure_counts_against_its_test(self) -> None:
        problems = verify(MANIFEST, log("--- PASS: TestA (0.1s)", "--- PASS: TestA (0.1s)", "    --- FAIL: TestB/case (0.0s)", "--- PASS: TestB (0.2s)"))
        self.assertTrue(any("TestB: failed" in p for p in problems), problems)


class DiscoverTest(unittest.TestCase):
    def test_finds_only_gated_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core = pathlib.Path(tmp)
            (core / "pkg" / "a").mkdir(parents=True)
            (core / "pkg" / "a" / "a_test.go").write_text(
                'package a\n\nfunc TestGated(t *testing.T) {\n\tu := os.Getenv("HELM_TEST_POSTGRES_URL")\n}\n\n'
                "func TestPlain(t *testing.T) {}\n"
            )
            self.assertEqual(discover(core), {("pkg/a", "TestGated")})

    def test_finds_tests_gated_through_a_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core = pathlib.Path(tmp)
            (core / "pkg" / "b").mkdir(parents=True)
            (core / "pkg" / "b" / "helper_test.go").write_text(
                'package b\n\nfunc openDB(t *testing.T) {\n\tif os.Getenv("HELM_TEST_POSTGRES_URL") == "" {\n\t\tt.Skip("x")\n\t}\n}\n\n'
                "func schema(t *testing.T) { openDB(t) }\n"
            )
            (core / "pkg" / "b" / "b_test.go").write_text(
                "package b\n\nfunc TestDirect(t *testing.T) { openDB(t) }\n\n"
                "func TestIndirect(t *testing.T) { schema(t) }\n\n"
                "func TestUnrelated(t *testing.T) {}\n"
            )
            self.assertEqual(discover(core), {("pkg/b", "TestDirect"), ("pkg/b", "TestIndirect")})

    def test_committed_manifest_matches_the_tree(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        manifest = parse_manifest((root / "scripts/ci/postgres-proofs.txt").read_text())
        self.assertEqual(discover(root / "core"), set(manifest))


if __name__ == "__main__":
    unittest.main()
