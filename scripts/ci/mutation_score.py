#!/usr/bin/env python3
"""Score a go-mutesting run and hold it to a threshold.

Only go-mutesting's own summary line counts as a measurement:

    The mutation score is 0.750000 (3 passed, 1 failed, 0 duplicated, 0 skipped, total is 4)

A run that printed no summary, executed no mutants, or exited non-zero has
measured nothing, and the gate fails rather than reporting a score. The script
used to print 100.00 for a zero exit with no parsable summary, which is what
go-mutesting does with `--no-exec` or when it finds no mutable files.

Usage: mutation_score.py LOG EXIT_STATUS THRESHOLD
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

SUMMARY = re.compile(
    r"The mutation score is (?P<score>[0-9]+(?:\.[0-9]+)?) "
    r"\((?P<passed>[0-9]+) passed, (?P<failed>[0-9]+) failed, "
    r"(?P<duplicated>[0-9]+) duplicated, (?P<skipped>[0-9]+) skipped, "
    r"total is (?P<total>[0-9]+)\)"
)


class NoMeasurement(Exception):
    """The run did not produce a mutation score that can be trusted."""


def parse_score(text: str, status: int) -> float:
    """Return the mutation score as a percentage, or raise NoMeasurement."""
    if status != 0:
        raise NoMeasurement(f"go-mutesting exited {status}")
    matches = list(SUMMARY.finditer(text))
    if not matches:
        raise NoMeasurement("go-mutesting printed no mutation score summary")
    if len(matches) > 1:
        raise NoMeasurement(f"go-mutesting printed {len(matches)} summaries; expected one")
    summary = matches[0]
    total = int(summary["total"])
    passed = int(summary["passed"])
    if total == 0:
        raise NoMeasurement("go-mutesting executed no mutants (total is 0)")
    # go-mutesting's own definition: killed mutants over executed mutants.
    return passed / total * 100


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    log, status, threshold = Path(argv[1]), int(argv[2]), float(argv[3])
    try:
        score = parse_score(log.read_text(errors="replace"), status)
    except NoMeasurement as exc:
        print(f"::error::mutation gate measured nothing: {exc}")
        return 1
    print(f"Mutation score: {score:.2f}% (threshold {threshold:.2f}%)")
    if score < threshold:
        print("::error::mutation score is below the threshold")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
