#!/usr/bin/env python3
"""Validate dependency manifests, lockfiles, and Dependabot coverage."""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIRED_FILES = [
    "core/go.mod",
    "core/go.sum",
    "sdk/go/go.mod",
    "sdk/go/go.sum",
    "sdk/python/pyproject.toml",
    "sdk/ts/package.json",
    "sdk/ts/package-lock.json",
    "sdk/rust/Cargo.toml",
    "sdk/rust/Cargo.lock",
    "sdk/java/pom.xml",
    "packages/design-system-core/package.json",
    "packages/design-system-core/package-lock.json",
    "apps/console/package.json",
    "apps/console/package-lock.json",
]
DEPENDABOT_DIRS = [
    "/core",
    "/sdk/go",
    "/tests/conformance",
    "/sdk/python",
    "/sdk/ts",
    "/packages/design-system-core",
    "/apps/console",
    "/sdk/rust",
    "/sdk/java",
]


def main() -> int:
    failures: list[str] = []
    for rel in REQUIRED_FILES:
        if not (ROOT / rel).exists():
            failures.append(f"missing dependency manifest or lockfile: {rel}")

    dependabot = ROOT / ".github" / "dependabot.yml"
    text = dependabot.read_text(errors="ignore") if dependabot.exists() else ""
    if not text:
        failures.append("missing .github/dependabot.yml")
    for directory in DEPENDABOT_DIRS:
        if not re.search(rf"directory:\s*{re.escape(directory)}\b", text):
            failures.append(f"Dependabot does not cover {directory}")

    if failures:
        print("Dependency hygiene check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"Dependency hygiene check passed: {len(REQUIRED_FILES)} files and {len(DEPENDABOT_DIRS)} Dependabot entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
