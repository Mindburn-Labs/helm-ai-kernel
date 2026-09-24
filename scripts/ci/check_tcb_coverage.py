#!/usr/bin/env python3
"""Hold the kernel TCB packages to their statement-coverage floors.

Reads a Go coverage profile and scripts/ci/tcb-coverage-floors.txt. Every
listed package must reach the `default` floor unless it carries its own lower,
frozen floor. The gate fails when the profile is empty, when a listed package
has no measured statements (it was not tested, or no longer exists), when any
package is below its floor, and when a package with its own floor has reached
the default, so that exceptions are removed as coverage catches up.

The coverage workflow used to compute this profile and print it without a
threshold (T-05), so no regression could fail it.

Usage:
  check_tcb_coverage.py packages FLOORS          print the go test package list
  check_tcb_coverage.py check PROFILE FLOORS     enforce the floors
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

MODULE_PREFIX = "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/"


class CoverageError(Exception):
    """The profile does not meet the floors, or cannot be judged."""


@dataclass(frozen=True)
class Floors:
    default: float
    # package -> its own frozen floor, or None for the default
    packages: dict[str, float | None]

    def floor(self, name: str) -> float:
        own = self.packages[name]
        return self.default if own is None else own


def parse_floors(text: str) -> Floors:
    default: float | None = None
    packages: dict[str, float | None] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) > 2:
            raise CoverageError(f"floors line {number}: want '<package> [percent]', got {raw!r}")
        name = fields[0]
        value = float(fields[1]) if len(fields) == 2 else None
        if value is not None and not 0 <= value <= 100:
            raise CoverageError(f"floors line {number}: {value} is not a percentage")
        if name == "default":
            if value is None:
                raise CoverageError(f"floors line {number}: default needs a percentage")
            default = value
        elif name in packages:
            raise CoverageError(f"floors line {number}: {name} listed twice")
        else:
            packages[name] = value
    if default is None:
        raise CoverageError("floors file has no 'default' floor")
    if not packages:
        raise CoverageError("floors file lists no packages")
    for name, own in packages.items():
        if own is not None and own >= default:
            raise CoverageError(f"{name}: its own floor {own} is not below the default {default}; drop it")
    return Floors(default=default, packages=packages)


def parse_profile(text: str) -> dict[str, tuple[int, int]]:
    """Return {package: (covered statements, total statements)}.

    A block can appear more than once (one entry per test binary that
    instrumented it); it counts once, as covered if any entry covered it.
    """
    lines = text.splitlines()
    if not lines or not lines[0].startswith("mode:"):
        raise CoverageError("not a Go coverage profile (no 'mode:' line)")
    blocks: dict[str, tuple[int, bool]] = {}
    for raw in lines[1:]:
        if not raw.strip():
            continue
        try:
            location, statements, count = raw.rsplit(" ", 2)
            n, hit = int(statements), int(count) > 0
        except ValueError as exc:
            raise CoverageError(f"malformed profile line: {raw!r}") from exc
        seen = blocks.get(location)
        blocks[location] = (n, hit or (seen is not None and seen[1]))
    if not blocks:
        raise CoverageError("coverage profile is empty; nothing was measured")
    totals: dict[str, tuple[int, int]] = {}
    for location, (n, hit) in blocks.items():
        package = location.split(":", 1)[0].rsplit("/", 1)[0]
        covered, total = totals.get(package, (0, 0))
        totals[package] = (covered + (n if hit else 0), total + n)
    return totals


def percent(covered: int, total: int) -> float:
    return covered / total * 100


def check(profile: dict[str, tuple[int, int]], floors: Floors) -> list[str]:
    """Return one report line per package plus the total; raise on failure."""
    report: list[str] = []
    failures: list[str] = []
    all_covered = all_total = 0
    for name in floors.packages:
        floor = floors.floor(name)
        covered, total = profile.get(MODULE_PREFIX + name, (0, 0))
        if total == 0:
            failures.append(f"{name}: no statements measured (package not tested or gone)")
            continue
        pct = percent(covered, total)
        all_covered += covered
        all_total += total
        status = "ok" if pct >= floor else "BELOW FLOOR"
        report.append(f"  {name:<20} {pct:6.2f}%  floor {floor:6.2f}%  {status}")
        if pct < floor:
            failures.append(f"{name}: {pct:.2f}% is below its floor of {floor:.2f}%")
        elif floors.packages[name] is not None and pct >= floors.default:
            failures.append(
                f"{name}: {pct:.2f}% has reached the default {floors.default:.2f}%; "
                "remove its own floor from the floors file"
            )
    if all_total:
        # Reported, not gated: the per-package floors are the gate.
        report.append(f"  {'all listed':<20} {percent(all_covered, all_total):6.2f}%")
    if failures:
        raise CoverageError("\n".join(report + ["", *failures]))
    return report


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 3 and argv[1] == "packages":
            floors = parse_floors(Path(argv[2]).read_text(encoding="utf-8"))
            print(" ".join(f"./pkg/{name}" for name in floors.packages))
            return 0
        if len(argv) == 4 and argv[1] == "check":
            profile = parse_profile(Path(argv[2]).read_text(encoding="utf-8"))
            floors = parse_floors(Path(argv[3]).read_text(encoding="utf-8"))
            print("\n".join(check(profile, floors)))
            print("TCB coverage gate passed.")
            return 0
    except CoverageError as exc:
        print(f"{exc}\n::error::TCB coverage gate failed", file=sys.stderr)
        return 1
    print(__doc__.strip().split("Usage:", 1)[1], file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
