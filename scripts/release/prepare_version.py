#!/usr/bin/env python3
"""Prepare a lockstep release version for repos that have enabled normalization."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import check_version_drift as drift

ROOT = Path(__file__).resolve().parents[2]


def update_exact(surface: dict[str, Any], version: str) -> bool:
    path = ROOT / surface["path"]
    expected = drift.fmt(surface.get("expected", "{version}"), version) + "\n"
    old = path.read_text(encoding="utf-8") if path.exists() else ""
    if old == expected:
        return False
    path.write_text(expected, encoding="utf-8")
    return True


def set_json_field(payload: dict[str, Any], field: str, value: str) -> None:
    current: Any = payload
    parts = field.split(".")
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


def update_json(surface: dict[str, Any], version: str) -> bool:
    path = ROOT / surface["path"]
    if not path.exists():
        return False
    payload = json.loads(path.read_text(encoding="utf-8"))
    before = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    set_json_field(payload, surface["field"], drift.fmt(surface.get("expected", "{version}"), version))
    after = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    if before == after:
        return False
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return True


def update_regex(surface: dict[str, Any], version: str) -> bool:
    path = ROOT / surface["path"]
    if not path.exists():
        return False
    if "replacement" not in surface:
        return False
    text = path.read_text(encoding="utf-8")
    replacement = drift.fmt(surface["replacement"], version)
    new_text, replacements = re.subn(surface["pattern"], replacement, text, count=int(surface.get("max_replacements", 0)), flags=re.MULTILINE)
    if replacements == 0:
        raise SystemExit(f"{surface['id']} did not match {drift.rel(path)}")
    if new_text == text:
        return False
    path.write_text(new_text, encoding="utf-8")
    return True


def update_tree_regex(surface: dict[str, Any], version: str) -> bool:
    base = ROOT / surface["path"]
    if not base.exists():
        return False
    if "replacement" not in surface:
        return False
    did_change = False
    for path in sorted(base.glob(surface["glob"])):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            replacement = drift.fmt(surface["replacement"], version)
            new_text, replacements = re.subn(surface["pattern"], replacement, text, count=int(surface.get("max_replacements", 0)), flags=re.MULTILINE)
            if new_text != text:
                path.write_text(new_text, encoding="utf-8")
                did_change = True
    return did_change


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def rewrite_sdk_manifests() -> list[str]:
    """Repin every SDK generated-file manifest against the bumped sources.

    The version surfaces rewrite the version literal inside generated files
    (types_gen.*), which changes their hashes; the manifests that pin those
    hashes are not version surfaces, so without this step every release bump
    leaves them stale and the regenerate-and-diff gate fails on content that
    is otherwise byte-identical. Each manifest is rewritten with its own
    recorded generator image and spec, so the pins stay exactly as reviewed.
    """
    rewritten: list[str] = []
    for manifest_path in sorted(ROOT.glob("sdk/*/generated.manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        sdk_dir = manifest_path.parent
        run(
            [
                "python3",
                "scripts/sdk/manifest.py",
                "write",
                str(sdk_dir.relative_to(ROOT)),
                manifest["generator"],
                manifest["source"]["spec"],
                *[entry["path"] for entry in manifest["files"]],
            ]
        )
        rewritten.append(str(manifest_path.relative_to(ROOT)))
    return rewritten


def warn_missing_console_pin(version: str) -> None:
    """Point at the one per-release declaration this script cannot write.

    The Console source pin names a reviewed Console commit and a provenance
    tag — a decision, not a derivation — so it cannot be generated here. The
    release job reads the pin file from the tag commit, which is why a
    missing row strands the tag; the console-sidecar-pin quality gate fails
    until the row exists, and this warning says so at the moment the version
    moves rather than at the first gate run.
    """
    pins_path = ROOT / "release" / "console-local-sidecar-pins.json"
    payload = json.loads(pins_path.read_text(encoding="utf-8"))
    wanted = f"v{version}"
    if not any(pin.get("kernel_release_version") == wanted for pin in payload.get("pins", [])):
        print(
            f"NOTE: {drift.rel(pins_path)} has no row for {wanted}; add one before tagging —"
            " the console-sidecar-pin gate fails until it exists, and a tag without it is stranded."
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="semver release version, for example 1.2.3")
    parser.add_argument("--contract", type=Path, default=drift.DEFAULT_CONTRACT)
    parser.add_argument("--force", action="store_true", help="prepare even when normalization_enabled is false")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    version = args.version[1:] if args.version.startswith("v") else args.version
    if not drift.SEMVER_RE.match(version):
        raise SystemExit(f"expected a semver version without prerelease: {args.version}")

    contract = drift.load_contract(args.contract)
    if not contract.get("normalization_enabled", False) and not args.force:
        print("normalization is disabled for this repo; version surfaces remain advisory until the normalization PR")
        run(["python3", "scripts/release/check_version_drift.py", "--expected-version", version, "--report", "local"])
        return 0

    changed: list[str] = []
    for surface in contract.get("local_surfaces", []):
        if surface.get("prepare", True) is False:
            continue
        kind = surface["kind"]
        if kind == "exact":
            did_change = update_exact(surface, version)
        elif kind == "json":
            did_change = update_json(surface, version)
        elif kind == "regex":
            did_change = update_regex(surface, version)
        elif kind == "tree_regex":
            did_change = update_tree_regex(surface, version)
        else:
            continue
        if did_change:
            changed.append(surface["id"])

    if changed:
        print("updated version surfaces:")
        for surface_id in changed:
            print(f"- {surface_id}")
    else:
        print("all prepared version surfaces were already current")
    rewritten = rewrite_sdk_manifests()
    if rewritten:
        print("repinned generated-file manifests:")
        for manifest_id in rewritten:
            print(f"- {manifest_id}")
    warn_missing_console_pin(version)
    run(["python3", "scripts/release/check_version_drift.py", "--expected-version", version, "local"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
