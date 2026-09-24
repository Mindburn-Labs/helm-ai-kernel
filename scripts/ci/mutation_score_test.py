#!/usr/bin/env python3
"""The mutation gate must fail when it measured nothing, not score 100%."""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from mutation_score import NoMeasurement, parse_score  # noqa: E402

SCRIPT = pathlib.Path(__file__).resolve().parent / "mutation_score.py"
SUMMARY = "The mutation score is {score} ({passed} passed, {failed} failed, 0 duplicated, {skipped} skipped, total is {total})\n"


def summary(passed: int, failed: int, skipped: int = 0) -> str:
    total = passed + failed + skipped
    score = passed / total if total else 0.0
    return SUMMARY.format(score=f"{score:f}", passed=passed, failed=failed, skipped=skipped, total=total)


class ParseScoreTest(unittest.TestCase):
    def test_reads_the_go_mutesting_summary(self) -> None:
        self.assertAlmostEqual(parse_score("PASS ...\n" + summary(3, 1), 0), 75.0)

    def test_skipped_mutants_count_against_the_score(self) -> None:
        self.assertAlmostEqual(parse_score(summary(8, 1, 1), 0), 80.0)

    def test_clean_exit_without_a_summary_is_not_a_score(self) -> None:
        # The old parser printed 100.00 here.
        with self.assertRaises(NoMeasurement):
            parse_score("Cannot do a mutation testing summary since no exec command was executed.\n", 0)
        with self.assertRaises(NoMeasurement):
            parse_score("", 0)

    def test_zero_mutants_is_not_a_score(self) -> None:
        with self.assertRaises(NoMeasurement):
            parse_score(summary(0, 0), 0)

    def test_tool_failure_is_not_a_score(self) -> None:
        with self.assertRaises(NoMeasurement):
            parse_score(summary(9, 1), 1)

    def test_lookalike_lines_are_not_a_summary(self) -> None:
        # The old parser accepted any "score: N%" and rescaled values <= 1,
        # so "mutation score: 1%" became 100%.
        for text in ("mutation score: 1%\n", "score is 0.5\n", "killed 10 survived 0\n"):
            with self.subTest(text=text), self.assertRaises(NoMeasurement):
                parse_score(text, 0)

    def test_two_summaries_are_ambiguous(self) -> None:
        with self.assertRaises(NoMeasurement):
            parse_score(summary(1, 0) + summary(0, 1), 0)


class CommandLineTest(unittest.TestCase):
    def run_gate(self, log: str, status: int, threshold: str = "80") -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write(log)
        try:
            return subprocess.run(
                [sys.executable, str(SCRIPT), handle.name, str(status), threshold],
                capture_output=True,
                text=True,
            )
        finally:
            pathlib.Path(handle.name).unlink()

    def test_passes_at_or_above_threshold(self) -> None:
        result = self.run_gate(summary(4, 1), 0)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Mutation score: 80.00%", result.stdout)

    def test_fails_below_threshold(self) -> None:
        self.assertEqual(self.run_gate(summary(3, 1), 0).returncode, 1)

    def test_fails_when_nothing_was_measured(self) -> None:
        result = self.run_gate("", 0)
        self.assertEqual(result.returncode, 1)
        self.assertIn("measured nothing", result.stdout)


if __name__ == "__main__":
    unittest.main()
