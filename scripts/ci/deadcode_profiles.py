#!/usr/bin/env python3
"""Combine RTA findings only across targets that compile the same source."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path

from security_findings import deadcode_keys


@dataclass
class Profile:
    dead: set[tuple[str, Path]]
    compiled: set[Path]


def read_profile(report: object, selected_files: str, module: Path) -> Profile:
    deadcode_keys(report)
    files = set()
    for line in selected_files.splitlines():
        if not line:
            continue
        path = Path(line)
        if not path.is_absolute():
            raise ValueError("go list must report absolute compiled source paths")
        files.add(path.resolve())
    if not files:
        raise ValueError("go list selected no source files")
    dead = set()
    for package in report or []:
        for function in package.get("Funcs") or []:
            filename = function["Position"]["File"]
            if not filename:
                raise ValueError("deadcode finding has no source file")
            path = (module / filename).resolve()
            if path not in files:
                raise ValueError(f"deadcode source was not compiled in its profile: {path}")
            dead.add((package["Path"] + " " + function["Name"], path))
    return Profile(dead, files)


def combined_findings(profiles: list[Profile]) -> list[str]:
    if not profiles:
        raise ValueError("at least one measured build profile is required")
    # Absence establishes reachability only when a target compiled the same
    # declaration. Unloaded packages and target-specific files stay separate.
    return sorted({key for profile in profiles for key, source in profile.dead
                   if all(source not in other.compiled or (key, source) in other.dead
                          for other in profiles)})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module-dir", type=Path, required=True)
    parser.add_argument("--profile", nargs=2, type=Path, action="append", required=True,
                        metavar=("DEADCODE_JSON", "COMPILED_SOURCES"))
    args = parser.parse_args()
    profiles = [read_profile(json.loads(dead.read_text()), sources.read_text(), args.module_dir)
                for dead, sources in args.profile]
    print("\n".join(combined_findings(profiles)))


if __name__ == "__main__":
    main()
