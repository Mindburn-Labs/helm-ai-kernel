#!/usr/bin/env python3
"""Resolve Core's module dependencies without its workspace or a warm cache."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
CORE_MODULE = "github.com/Mindburn-Labs/helm-ai-kernel/core"
SDK_MODULE = "github.com/Mindburn-Labs/helm-ai-kernel/sdk/go"
FIRST_PARTY = "github.com/Mindburn-Labs/"
PRIVATE_PATTERN = FIRST_PARTY + "*"


def go_json(args: list[str], directory: Path, env: dict[str, str]) -> dict:
    try:
        output = subprocess.check_output(["go", *args], cwd=directory, env=env, text=True)
    except subprocess.CalledProcessError as exc:
        if exc.output:
            print(exc.output, file=sys.stderr)
        raise
    return json.loads(output)


def check_closure(core: Path) -> None:
    # Download from a copy so even an unexpected Go lockfile update cannot
    # silently repair the source under test. Nothing from go.work is copied.
    original = {name: (core / name).read_bytes() for name in ("go.mod", "go.sum")}
    with tempfile.TemporaryDirectory(prefix="helm-core-module-closure-") as temporary:
        scratch = Path(temporary)
        module = scratch / "core"
        cache = scratch / "gomodcache"
        module.mkdir()
        cache.mkdir()
        for name in original:
            shutil.copyfile(core / name, module / name)
        env = dict(os.environ)
        env.update(
            GOWORK="off",
            GOMODCACHE=str(cache),
            GOFLAGS="-mod=readonly",
            GONOPROXY=PRIVATE_PATTERN,
        )
        declared = go_json(["mod", "edit", "-json"], module, env)
        if declared["Module"]["Path"] != CORE_MODULE:
            raise RuntimeError("closure guard must read the Core module")
        for replacement in declared.get("Replace") or []:
            if replacement["Old"]["Path"].startswith(FIRST_PARTY) or not replacement["New"].get("Version"):
                raise RuntimeError("first-party or local module replacement hides standalone resolution")
        requirements = {
            entry["Path"]: entry["Version"]
            for entry in declared.get("Require") or []
            if entry["Path"].startswith(FIRST_PARTY)
        }
        if SDK_MODULE not in requirements:
            raise RuntimeError("Core must declare its Go SDK dependency")
        # Check first-party requirements directly before downloading the full
        # closure. A proxy's retained pseudo-version must not hide an origin
        # revision that a new standalone consumer cannot fetch.
        direct = dict(env, GOPROXY="direct")
        for path, version in sorted(requirements.items()):
            downloaded = go_json(["mod", "download", "-json", path + "@" + version], module, direct)
            if downloaded.get("Error") or downloaded.get("Reuse"):
                raise RuntimeError("first-party module was not freshly downloaded")
            if (downloaded.get("Path"), downloaded.get("Version")) != (path, version):
                raise RuntimeError("first-party download does not match Core's requirement")
            if not Path(downloaded["Dir"]).resolve().is_relative_to(cache.resolve()):
                raise RuntimeError("first-party download escaped the fresh module cache")
            origin = downloaded.get("Origin") or {}
            if not origin.get("Hash"):
                raise RuntimeError("direct module download has no source origin")
            if not downloaded.get("Sum") or not downloaded.get("GoModSum"):
                raise RuntimeError("direct module download has no authenticated checksums")
            print(json.dumps({
                "cold_direct_dependency": path,
                "version": version,
                "origin_commit": origin["Hash"],
                "origin_ref": origin.get("Ref"),
                "sum": downloaded.get("Sum"),
                "go_mod_sum": downloaded.get("GoModSum"),
            }, sort_keys=True), flush=True)
        # Public third-party dependencies retain Go's configured proxy policy;
        # first-party dependencies still bypass it through GONOPROXY above.
        subprocess.run(["go", "mod", "download"], cwd=module, env=env, check=True)
        selected = go_json(["list", "-m", "-json", SDK_MODULE], module, env)
        if selected.get("Replace") or selected.get("Version") != requirements[SDK_MODULE]:
            raise RuntimeError("standalone module graph substituted the declared SDK")
        for name, content in original.items():
            if (module / name).read_bytes() != content or (core / name).read_bytes() != content:
                raise RuntimeError(f"cold module closure changed {name}")
        print("Core cold standalone module closure passed.", flush=True)


if __name__ == "__main__":
    check_closure(ROOT / "core")
