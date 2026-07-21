#!/usr/bin/env python3
"""Require every declared ReasonCode to be reachable.

A reason code that is declared and enumerated but never emitted is an
unenforceable contract: it reads as coverage in review and produces nothing at
runtime. ERR_ASSUMPTION_STALE is the canonical example — declared, given a
conformance vector, never returned by any code path.

A code passes if non-test code can emit it, or if it is recorded in
reason-codes-known-unreachable.txt with an owner and a tracking issue. The
allowlist is also checked in reverse: an entry whose code has since become
reachable fails, so the list burns down instead of rotting.

Matching is deliberately qualified. Two packages shadow these names and must
not count as emissions:
  - core/pkg/conform/reason_codes.go reuses the Go identifiers
  - core/pkg/connectors/ton/acton/errors.go reuses the wire values
So an emission is `contracts.<Ident>` anywhere, or a bare `<Ident>` inside
core/pkg/contracts/ only. Lines assigning ExpectedReasonCode are conformance
expectations — assertions about required behavior, not emissions — and are
excluded.
"""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERDICT = ROOT / "core" / "pkg" / "contracts" / "verdict.go"
CONTRACTS_DIR = ROOT / "core" / "pkg" / "contracts"
SEARCH_ROOT = ROOT / "core"
ALLOWLIST = pathlib.Path(__file__).resolve().parent / "reason-codes-known-unreachable.txt"

DECL_RE = re.compile(r'^\s+(Reason[A-Za-z0-9_]+)\s+ReasonCode\s*=\s*"([^"]+)"', re.M)
EXPECTATION_RE = re.compile(r"ExpectedReasonCode\s*:")

SKIP_PARTS = {".git", "node_modules", "vendor", "worktrees", "testdata"}


def go_sources() -> list[pathlib.Path]:
    out = []
    for path in SEARCH_ROOT.rglob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        if path == VERDICT:
            continue
        # Relative to SEARCH_ROOT — an absolute-path check would match the
        # checkout's own location (e.g. running from .claude/worktrees/...)
        # and silently skip every file.
        if SKIP_PARTS & set(path.relative_to(SEARCH_ROOT).parts):
            continue
        out.append(path)
    return out


def main() -> int:
    source = VERDICT.read_text(encoding="utf-8")
    declared = {ident: wire for ident, wire in DECL_RE.findall(source)}
    if not declared:
        print(f"error: no ReasonCode declarations parsed from {VERDICT}", file=sys.stderr)
        return 2

    emitted: set[str] = set()
    for path in go_sources():
        in_contracts_pkg = CONTRACTS_DIR in path.parents
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line in text.splitlines():
            if EXPECTATION_RE.search(line):
                continue
            for ident in declared:
                if ident in emitted:
                    continue
                if f"contracts.{ident}" in line:
                    emitted.add(ident)
                elif in_contracts_pkg and re.search(rf"\b{ident}\b", line):
                    emitted.add(ident)

    allowed: set[str] = set()
    if ALLOWLIST.exists():
        for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                allowed.add(line.split()[0])

    unreachable = sorted(set(declared) - emitted - allowed)
    stale = sorted(allowed & emitted)
    unknown = sorted(allowed - set(declared))

    if unreachable:
        print("Declared ReasonCodes that no non-test code can emit:")
        for ident in unreachable:
            print(f"  {ident:<45} {declared[ident]}")
        print(
            f"\nEmit each from the path that should produce it, or add it to\n"
            f"{ALLOWLIST.relative_to(ROOT)} with an owner and a tracking issue."
        )

    if stale:
        print("\nAllowlisted ReasonCodes that are now emitted — remove these entries:")
        for ident in stale:
            print(f"  {ident:<45} {declared[ident]}")

    if unknown:
        print("\nAllowlist entries that are not declared ReasonCodes:")
        for ident in unknown:
            print(f"  {ident}")

    if unreachable or stale or unknown:
        return 1

    print(f"reason-code reachability: {len(declared)} declared, {len(emitted)} emitted, {len(allowed)} allowlisted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
