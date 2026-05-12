#!/usr/bin/env python3
"""Check SQL migration naming, coverage-ledger rows, and destructive safety."""
from __future__ import annotations

import csv
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MIGRATION_RE = re.compile(r"^\d{3}_[a-z0-9_]+\.sql$")
DESTRUCTIVE_RE = re.compile(r"\b(DROP|TRUNCATE)\b", re.IGNORECASE)


def coverage_sources() -> set[str]:
    path = ROOT / "docs" / "documentation-coverage.csv"
    with path.open(newline="") as handle:
        return {row["source_path"] for row in csv.DictReader(handle)}


def main() -> int:
    failures: list[str] = []
    sources = coverage_sources()
    migrations = sorted((ROOT / "core").glob("**/migrations/*.sql"))
    if not migrations:
        failures.append("no SQL migrations found under core/**/migrations")

    by_dir: dict[Path, list[Path]] = {}
    for path in migrations:
        by_dir.setdefault(path.parent, []).append(path)
        rel = path.relative_to(ROOT).as_posix()
        if not MIGRATION_RE.match(path.name):
            failures.append(f"{rel} must use NNN_lower_snake_case.sql naming")
        if rel not in sources:
            failures.append(f"{rel} is missing from docs/documentation-coverage.csv")
        text = path.read_text(errors="ignore")
        if DESTRUCTIVE_RE.search(text) and "irreversible" not in text.lower():
            failures.append(f"{rel} contains DROP/TRUNCATE without an irreversible migration note")

    for directory, paths in by_dir.items():
        numbers = [path.name.split("_", 1)[0] for path in paths]
        if len(numbers) != len(set(numbers)):
            failures.append(f"{directory.relative_to(ROOT)} has duplicate migration sequence numbers")
        expected = [f"{index:03d}" for index in range(1, len(paths) + 1)]
        if sorted(numbers) != expected:
            failures.append(f"{directory.relative_to(ROOT)} sequence should be contiguous from 001")

    if failures:
        print("Migration coverage check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Migration coverage check passed: {len(migrations)} migration file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
