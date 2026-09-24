#!/usr/bin/env python3
"""Turn security-scanner reports into stable finding keys and hold them to a
frozen allowlist.

A key names one finding without its line number, so an unrelated edit that
moves code does not look like a new finding:

  gosec     <rule> <file> <sha256 of the offending source line, 12 hex>
  gitleaks  <rule> <file> <sha256 of the matched secret, 12 hex>

The secret itself is never printed. `compare` fails on any finding not in the
allowlist (new) and on any allowlist line no finding matches (stale), so the
allowlist can only shrink. Keys are a multiset: two identical findings in one
file need two allowlist lines.

Usage:
  security_findings.py gosec-keys REPORT ROOT         golangci-lint JSON (--path-mode abs)
  security_findings.py gitleaks-keys REPORT           gitleaks JSON report
  security_findings.py govulncheck-called REPORT      OSV ids reachable from code
  security_findings.py compare ALLOWLIST KEYS         exit 1 on new or stale keys
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


class ReportError(Exception):
    """A report could not be read, so nothing was measured."""


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def gosec_keys(report: dict[str, Any], root: str) -> list[str]:
    if "Issues" not in report:
        raise ReportError("golangci-lint report has no Issues field")
    keys = []
    for issue in report["Issues"] or []:
        if issue.get("FromLinter") != "gosec":
            continue
        rule = issue["Text"].split(":", 1)[0].strip()
        path = os.path.relpath(issue["Pos"]["Filename"], root)
        source = "\n".join(line.strip() for line in issue.get("SourceLines") or [])
        keys.append(f"{rule} {path} {digest(source)}")
    return sorted(keys)


def gitleaks_keys(report: list[dict[str, Any]]) -> list[str]:
    if not isinstance(report, list):
        raise ReportError("gitleaks report is not a list of findings")
    return sorted(f"{f['RuleID']} {f['File']} {digest(f['Secret'])}" for f in report)


def json_stream(text: str) -> Iterable[dict[str, Any]]:
    decoder = json.JSONDecoder()
    index = 0
    while True:
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            return
        value, index = decoder.raw_decode(text, index)
        yield value


def govulncheck_called(text: str) -> list[str]:
    """OSV ids whose trace reaches a function: the code calls the vulnerable symbol."""
    saw_config = False
    called = set()
    for message in json_stream(text):
        saw_config = saw_config or "config" in message
        finding = message.get("finding")
        if finding and finding.get("trace") and finding["trace"][0].get("function"):
            called.add(finding["osv"])
    if not saw_config:
        raise ReportError("govulncheck JSON stream has no config message; the scan did not run")
    return sorted(called)


def parse_allowlist(text: str) -> Counter[str]:
    return Counter(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#"))


def compare(allowed: Counter[str], found: Counter[str]) -> tuple[list[str], list[str]]:
    new = sorted((found - allowed).elements())
    stale = sorted((allowed - found).elements())
    return new, stale


def main(argv: list[str]) -> int:
    try:
        command, args = argv[1], argv[2:]
        if command == "gosec-keys" and len(args) == 2:
            print("\n".join(gosec_keys(json.loads(Path(args[0]).read_text()), args[1])))
        elif command == "gitleaks-keys" and len(args) == 1:
            print("\n".join(gitleaks_keys(json.loads(Path(args[0]).read_text()))))
        elif command == "govulncheck-called" and len(args) == 1:
            print("\n".join(govulncheck_called(Path(args[0]).read_text())))
        elif command == "compare" and len(args) == 2:
            allowed = parse_allowlist(Path(args[0]).read_text())
            found = parse_allowlist(Path(args[1]).read_text())
            new, stale = compare(allowed, found)
            for key in new:
                print(f"::error::new finding, not in {args[0]}: {key}")
            for key in stale:
                print(f"::error::allowlisted finding no longer occurs; delete this line from {args[0]}: {key}")
            print(f"{sum(found.values())} finding(s), {sum(allowed.values())} allowlisted, {len(new)} new, {len(stale)} stale")
            return 1 if new or stale else 0
        else:
            print(__doc__.strip().split("Usage:", 1)[1], file=sys.stderr)
            return 2
    except (ReportError, json.JSONDecodeError, KeyError, OSError, IndexError) as exc:
        print(f"::error::cannot read the scanner report: {exc!r}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
