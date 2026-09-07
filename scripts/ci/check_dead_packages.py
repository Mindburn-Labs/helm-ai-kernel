#!/usr/bin/env python3
"""Importer-less package census for core/pkg.

Lists every ``core/pkg/...`` package that no other package in the repository
imports from non-test code. The census spans every Go module in the checkout
(``core``, ``tools/*``, ``tests/*``, ``sdk/go``, ``examples/*``), so a package
that only the conformance suite or an SDK example imports still counts as
imported. Test-only importers (``_test.go`` files in other packages) are
reported separately and do not rescue a package.

The gate exits non-zero when any importer-less package is not covered by the
allowlist. The allowlist names packages that are deliberately public library
surface; every line carries a one-line reason.

Usage:

    python3 scripts/ci/check_dead_packages.py [--allowlist FILE] [--format text|json|markdown]

Run from the repository root. Every ``go`` invocation runs with ``GOWORK=off``
so the census matches CI, not the workspace ``go.work``.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

MODULE_PREFIX = "github.com/Mindburn-Labs/helm-ai-kernel/core/"
TARGET_PREFIX = MODULE_PREFIX + "pkg/"
CMD_PREFIX = MODULE_PREFIX + "cmd/"
SKIP_DIRS = {"node_modules", "vendor", ".git", "target", "dist"}
DEFAULT_ALLOWLIST = Path("scripts/ci/dead-packages-allowlist.txt")

GO_LIST_FIELDS = (
    "ImportPath,Name,Dir,GoFiles,TestGoFiles,XTestGoFiles,"
    "Imports,TestImports,XTestImports,Error"
)


@dataclass
class Package:
    import_path: str
    name: str
    directory: str
    go_files: list[str]
    test_go_files: list[str]
    imports: set[str]
    test_imports: set[str]
    module_dir: str
    error: str | None = None


@dataclass
class Finding:
    import_path: str
    rel_path: str
    test_only_importers: list[str] = field(default_factory=list)
    reachable_from_cmd: bool = False
    has_tests: bool = False
    allowlisted: bool = False
    allow_reason: str = ""


def discover_modules(root: Path) -> list[Path]:
    modules: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        if "go.mod" in filenames:
            modules.append(Path(dirpath))
    return sorted(modules)


def go_list(module_dir: Path) -> list[Package]:
    env = dict(os.environ)
    env["GOWORK"] = "off"
    env.setdefault("GOFLAGS", "-mod=mod")
    proc = subprocess.run(
        ["go", "list", "-e", f"-json={GO_LIST_FIELDS}", "./..."],
        cwd=module_dir,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 and not proc.stdout.strip():
        raise RuntimeError(f"go list failed in {module_dir}: {proc.stderr.strip()}")
    packages: list[Package] = []
    decoder = json.JSONDecoder()
    text = proc.stdout
    pos = 0
    while pos < len(text):
        while pos < len(text) and text[pos].isspace():
            pos += 1
        if pos >= len(text):
            break
        obj, pos = decoder.raw_decode(text, pos)
        err = obj.get("Error")
        packages.append(
            Package(
                import_path=obj["ImportPath"],
                name=obj.get("Name", ""),
                directory=obj.get("Dir", ""),
                go_files=obj.get("GoFiles") or [],
                test_go_files=(obj.get("TestGoFiles") or []) + (obj.get("XTestGoFiles") or []),
                imports=set(obj.get("Imports") or []),
                test_imports=set(obj.get("TestImports") or []) | set(obj.get("XTestImports") or []),
                module_dir=str(module_dir),
                error=err.get("Err") if isinstance(err, dict) else None,
            )
        )
    return packages


def load_allowlist(path: Path | None) -> dict[str, str]:
    allow: dict[str, str] = {}
    if path is None or not path.exists():
        return allow
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" not in line:
            raise ValueError(f"{path}:{lineno}: allowlist line needs '<package> # <reason>'")
        pkg, reason = line.split("#", 1)
        pkg = pkg.strip()
        reason = reason.strip()
        if not pkg or not reason:
            raise ValueError(f"{path}:{lineno}: allowlist line needs '<package> # <reason>'")
        if not pkg.startswith("core/pkg/"):
            raise ValueError(f"{path}:{lineno}: allowlist entries are core/pkg/... paths, got {pkg!r}")
        allow[pkg] = reason
    return allow


def census(root: Path, allowlist: dict[str, str]) -> tuple[list[Finding], dict[str, int]]:
    by_path: dict[str, Package] = {}
    for module_dir in discover_modules(root):
        for pkg in go_list(module_dir):
            by_path.setdefault(pkg.import_path, pkg)

    importers: dict[str, set[str]] = {}
    test_importers: dict[str, set[str]] = {}
    for pkg in by_path.values():
        for dep in pkg.imports:
            if dep != pkg.import_path:
                importers.setdefault(dep, set()).add(pkg.import_path)
        for dep in pkg.test_imports:
            if dep != pkg.import_path:
                test_importers.setdefault(dep, set()).add(pkg.import_path)

    reachable: set[str] = set()
    stack = [p for p, pkg in by_path.items() if pkg.name == "main" and p.startswith(CMD_PREFIX)]
    while stack:
        current = stack.pop()
        if current in reachable:
            continue
        reachable.add(current)
        pkg = by_path.get(current)
        if pkg is None:
            continue
        stack.extend(dep for dep in pkg.imports if dep in by_path and dep not in reachable)

    targets = sorted(p for p in by_path if p.startswith(TARGET_PREFIX))
    findings: list[Finding] = []
    for path in targets:
        pkg = by_path[path]
        if not pkg.go_files:
            continue  # test-only directory, nothing to import
        if importers.get(path):
            continue
        rel = "core/" + path[len(MODULE_PREFIX):]
        finding = Finding(
            import_path=path,
            rel_path=rel,
            test_only_importers=sorted(
                "core/" + i[len(MODULE_PREFIX):] if i.startswith(MODULE_PREFIX) else i
                for i in test_importers.get(path, set())
            ),
            reachable_from_cmd=path in reachable,
            has_tests=bool(pkg.test_go_files),
        )
        if rel in allowlist:
            finding.allowlisted = True
            finding.allow_reason = allowlist[rel]
        findings.append(finding)

    summary = {
        "total_core_pkg_packages": sum(1 for p in targets if by_path[p].go_files),
        "importer_less": len(findings),
        "with_test_only_importers": sum(1 for f in findings if f.test_only_importers),
        "unreachable_from_cmd": sum(1 for p in targets if by_path[p].go_files and p not in reachable),
        "allowlisted": sum(1 for f in findings if f.allowlisted),
        "unlisted": sum(1 for f in findings if not f.allowlisted),
    }
    stale = sorted(set(allowlist) - {f.rel_path for f in findings})
    summary["stale_allowlist_entries"] = len(stale)
    return findings, summary


def render_text(findings: list[Finding], summary: dict[str, int], allowlist: dict[str, str]) -> str:
    lines = []
    for f in findings:
        flags = []
        if f.test_only_importers:
            flags.append(f"test-only-importers={len(f.test_only_importers)}")
        if f.has_tests:
            flags.append("has-tests")
        if f.allowlisted:
            flags.append(f"allowlisted: {f.allow_reason}")
        lines.append(f"{f.rel_path}\t{' '.join(flags)}".rstrip())
    stale = sorted(set(allowlist) - {f.rel_path for f in findings})
    for entry in stale:
        lines.append(f"STALE allowlist entry (package now has importers or is gone): {entry}")
    lines.append("")
    lines.append(
        "dead-packages: {total_core_pkg_packages} core/pkg packages, "
        "{importer_less} importer-less ({with_test_only_importers} with test-only importers), "
        "{unreachable_from_cmd} unreachable from any cmd/, "
        "{allowlisted} allowlisted, {unlisted} unlisted".format(**summary)
    )
    return "\n".join(lines)


def render_markdown(findings: list[Finding]) -> str:
    lines = ["| package | test-only importers | tests? | reachable from cmd | allowlisted |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append(
            f"| `{f.rel_path}` | {len(f.test_only_importers)} | {'yes' if f.has_tests else 'no'} | "
            f"{'yes' if f.reachable_from_cmd else 'no'} | {f.allow_reason or 'no'} |"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", default=".", help="repository root (default: cwd)")
    parser.add_argument("--allowlist", default=str(DEFAULT_ALLOWLIST), help="allowlist file; '-' disables it")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    allow_path = None if args.allowlist == "-" else (root / args.allowlist)
    try:
        allowlist = load_allowlist(allow_path)
        findings, summary = census(root, allowlist)
    except (RuntimeError, ValueError) as exc:
        print(f"dead-packages: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps({"summary": summary, "packages": [f.__dict__ for f in findings]}, indent=2, sort_keys=True))
    elif args.format == "markdown":
        print(render_markdown(findings))
    else:
        print(render_text(findings, summary, allowlist))

    if summary["unlisted"] or summary["stale_allowlist_entries"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
