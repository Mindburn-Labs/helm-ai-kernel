#!/usr/bin/env python3
"""Generated-file manifest tool for HELM SDKs (HELM-W3).

Each SDK carries a ``generated.manifest.json`` at its package root describing
the files produced by ``scripts/sdk/gen.sh``: the generator image (digest
pinned), the source OpenAPI spec hash, and the sha256 of every generated file.

The manifest is deterministic (sorted keys, no timestamps) so the
regenerate-and-diff gate can commit it and diff it like any other output.

Usage:
    manifest.py write  <sdk_dir> <generator_image> <spec_path> <file>...
    manifest.py verify <sdk_dir>

``verify`` is fail-closed: a missing manifest, a missing generated file, or
any hash mismatch exits non-zero.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

MANIFEST_NAME = "generated.manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fail(message: str) -> SystemExit:
    return SystemExit(f"manifest error: {message}")


def write_manifest(sdk_dir: Path, generator_image: str, spec_path: Path, files: list[str]) -> Path:
    if not sdk_dir.is_dir():
        raise _fail(f"sdk directory not found: {sdk_dir}")
    if not spec_path.is_file():
        raise _fail(f"openapi spec not found: {spec_path}")
    if not files:
        raise _fail("no generated files recorded")

    entries = []
    for rel in sorted(files):
        target = sdk_dir / rel
        if not target.is_file():
            raise _fail(f"generated file not found: {target}")
        entries.append({"path": rel, "sha256": _sha256(target)})

    manifest = {
        "sdk": sdk_dir.name,
        "generator": generator_image,
        "source": {
            "spec": f"api/openapi/{spec_path.name}",
            "sha256": _sha256(spec_path),
        },
        "files": entries,
    }
    out = sdk_dir / MANIFEST_NAME
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def verify_manifest(sdk_dir: Path) -> list[str]:
    """Return a list of problems; empty list means the SDK is consistent."""
    problems: list[str] = []
    manifest_path = sdk_dir / MANIFEST_NAME
    if not manifest_path.is_file():
        return [f"missing manifest: {manifest_path}"]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"unparseable manifest {manifest_path}: {exc}"]

    if not isinstance(manifest, dict):
        return [f"manifest {manifest_path} is not a JSON object"]

    sdk_root = sdk_dir.resolve()
    repo_root = sdk_root.parent.parent

    def _contained(base: Path, rel: str) -> Path | None:
        """Resolve rel under base; None when it escapes or is absolute."""
        candidate = Path(rel)
        if candidate.is_absolute() or not rel:
            return None
        resolved = (base / candidate).resolve()
        if resolved != base and base not in resolved.parents:
            return None
        return resolved

    # The recorded source spec must also match disk: a spec change or a
    # tampered source.sha256/source.spec entry is drift like any other.
    source = manifest.get("source")
    if not isinstance(source, dict):
        problems.append(f"manifest {manifest_path} has no source object")
    else:
        spec_rel = source.get("spec", "")
        spec_expected = source.get("sha256", "")
        if not isinstance(spec_rel, str) or not isinstance(spec_expected, str) or not spec_rel or not spec_expected:
            problems.append(f"manifest {manifest_path} has an incomplete source entry: {source!r}")
        else:
            spec_target = _contained(repo_root, spec_rel)
            if spec_target is None:
                problems.append(f"manifest {manifest_path} source spec escapes the repo: {spec_rel!r}")
            elif not spec_target.is_file():
                problems.append(f"source spec missing on disk: {spec_target}")
            else:
                spec_actual = _sha256(spec_target)
                if spec_actual != spec_expected:
                    problems.append(
                        f"source spec hash mismatch: {spec_target} "
                        f"(manifest {spec_expected[:12]}..., disk {spec_actual[:12]}...)"
                    )

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return problems + [f"manifest {manifest_path} records no files"]

    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            problems.append(f"manifest {manifest_path} has a non-object entry: {entry!r}")
            continue
        rel = entry.get("path", "")
        expected = entry.get("sha256", "")
        if not isinstance(rel, str) or not isinstance(expected, str) or not rel or not expected:
            problems.append(f"manifest {manifest_path} has an incomplete entry: {entry!r}")
            continue
        if rel in seen:
            problems.append(f"manifest {manifest_path} lists {rel} twice")
            continue
        seen.add(rel)
        target = _contained(sdk_root, rel)
        if target is None:
            problems.append(f"manifest {manifest_path} entry escapes the SDK directory: {rel!r}")
            continue
        if not target.is_file():
            problems.append(f"generated file missing on disk: {target}")
            continue
        actual = _sha256(target)
        if actual != expected:
            problems.append(
                f"hash mismatch: {target} (manifest {expected[:12]}..., disk {actual[:12]}...)"
            )
    return problems


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    command = argv[1]
    if command == "write":
        if len(argv) < 6:
            print(__doc__, file=sys.stderr)
            return 2
        out = write_manifest(Path(argv[2]), argv[3], Path(argv[4]), argv[5:])
        print(f"  [manifest] wrote {out}")
        return 0
    if command == "verify":
        problems = verify_manifest(Path(argv[2]))
        if problems:
            for problem in problems:
                print(f"  [manifest] FAIL {problem}", file=sys.stderr)
            return 1
        print(f"  [manifest] ok {Path(argv[2]).name}")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
