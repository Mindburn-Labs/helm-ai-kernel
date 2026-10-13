#!/usr/bin/env python3
"""Validate dependency manifests, lockfiles, and Dependabot coverage."""
from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

import yaml


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
]
SDK_MANIFESTS = {
    "package.json": "npm",
    "pyproject.toml": "pip",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
}


def manifest_ecosystem(path: str) -> str | None:
    manifest = Path(path)
    if manifest.name == "go.mod":
        return "gomod"
    if not path.startswith("sdk/"):
        return None
    if fnmatch.fnmatchcase(manifest.name, "requirements*.txt"):
        return "pip"
    return SDK_MANIFESTS.get(manifest.name)


def coverage_failures(root: Path, text: str, manifests: list[str]) -> list[str]:
    config = yaml.safe_load(text)
    if not isinstance(config, dict) or config.get("version") != 2:
        raise ValueError("Dependabot configuration must have version: 2")
    updates = config.get("updates")
    if not isinstance(updates, list) or not updates:
        raise ValueError("Dependabot updates must be a nonempty list")

    covered: dict[str, set[Path]] = {}
    for entry in updates:
        if not isinstance(entry, dict) or not isinstance(entry.get("package-ecosystem"), str):
            raise ValueError("each Dependabot update must name a package-ecosystem")
        if ("directory" in entry) == ("directories" in entry):
            raise ValueError("each Dependabot update must use directory or directories")
        patterns = entry.get("directories", [entry.get("directory")])
        if not isinstance(patterns, list) or not patterns or not all(
            isinstance(pattern, str) and pattern for pattern in patterns
        ):
            raise ValueError("Dependabot directories must contain nonempty strings")
        directories = covered.setdefault(entry["package-ecosystem"], set())
        # An update for a different target branch does not cover the default branch.
        if entry.get("target-branch") not in (None, "main"):
            continue
        for pattern in patterns:
            relative = pattern.lstrip("/")
            if ".." in Path(relative).parts:
                raise ValueError("Dependabot directories must stay inside the repository")
            if "directory" in entry or not relative:
                directories.add(root / relative)
            else:
                directories.update(path for path in root.glob(relative) if path.is_dir())

    failures = []
    for manifest in manifests:
        ecosystem = manifest_ecosystem(manifest)
        if ecosystem and (root / manifest).parent not in covered.get(ecosystem, set()):
            failures.append(f"Dependabot does not cover {manifest} ({ecosystem})")
    return failures


def main() -> int:
    failures: list[str] = []
    for rel in REQUIRED_FILES:
        if not (ROOT / rel).exists():
            failures.append(f"missing dependency manifest or lockfile: {rel}")

    dependabot = ROOT / ".github" / "dependabot.yml"
    text = dependabot.read_text(errors="ignore") if dependabot.exists() else ""
    if not text:
        failures.append("missing .github/dependabot.yml")
    try:
        manifests = subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=ROOT, text=True
        ).rstrip("\0").split("\0")
        failures.extend(coverage_failures(ROOT, text, manifests))
    except (yaml.YAMLError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        failures.append(f"cannot evaluate Dependabot coverage: {exc}")

    if failures:
        print("Dependency hygiene check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    count = sum(manifest_ecosystem(path) is not None for path in manifests)
    print(f"Dependency hygiene check passed: {len(REQUIRED_FILES)} required files and {count} covered dependency manifests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
