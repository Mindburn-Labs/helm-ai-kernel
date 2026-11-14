#!/usr/bin/env python3
"""Reject source files outside the Git index or missing from the checkout."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[2]
# The source scope of the retired kernel digest manifest. Its untracked-file
# check remains useful: compilers do not honor .gitignore. Enterprise owns a
# separate inventory for its mirrored paths.
SOURCE_ROOTS = (
    "core/pkg/kernel", "core/pkg/contracts", "core/pkg/crypto",
    "core/pkg/evidencepack", "core/pkg/proofgraph", "core/pkg/receipts",
    "core/pkg/verifier", "core/pkg/connectors/sandbox", "core/pkg/conformance",
    "core/pkg/safedep", "core/pkg/audit", "core/pkg/api", "core/pkg/guardian",
    "core/pkg/packs", "protocols", "schemas",
)


def inventory(root: Path, flag: str) -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z", flag, "--", *SOURCE_ROOTS],
        cwd=root, capture_output=True, check=True,
    )
    return [os.fsdecode(path) for path in result.stdout.split(b"\0") if path]


def check(root: Path) -> list[str]:
    failures = [f"missing source directory: {path}" for path in SOURCE_ROOTS
                if not (root / path).is_dir()]
    tracked = inventory(root, "--cached")
    if not tracked:
        failures.append("source inventory is empty")
    failures.extend(f"tracked source file is missing: {path!r}" for path in tracked
                    if not (root / path).is_file())
    # Deliberately omit --exclude-standard so ignored files are checked too.
    failures.extend(f"source file is not in the Git index: {path!r}"
                    for path in inventory(root, "--others"))
    return failures


def main() -> int:
    try:
        failures = check(ROOT)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"source tree inventory failed: {exc}")
        return 2
    for failure in failures:
        print(f"ERROR: {failure}")
    if failures:
        return 1
    print("Source tree check passed: declared source paths exist and contain only indexed files.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
