#!/usr/bin/env python3
"""Fail if open GitHub PRs expose non-OSS infrastructure terminology."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys

REPO = "Mindburn-Labs/helm-oss"

TERMS = [
    re.compile(r"\bcommercial\b", re.IGNORECASE),
    re.compile(r"\bDigitalOcean\b", re.IGNORECASE),
    re.compile(r"\bDO proxy\b", re.IGNORECASE),
    re.compile(r"\bproduction proxy\b", re.IGNORECASE),
    re.compile(r"\bcustomer infrastructure\b", re.IGNORECASE),
    re.compile(r"\btenant infrastructure\b", re.IGNORECASE),
    re.compile(r"\boss\.mindburn\.org\b", re.IGNORECASE),
    re.compile(r"\bprivate control plane\b", re.IGNORECASE),
]


def main() -> int:
    if not shutil.which("gh"):
        print("gh CLI is required for PR boundary verification", file=sys.stderr)
        return 1

    try:
        raw = subprocess.check_output(
            [
                "gh",
                "pr",
                "list",
                "--repo",
                REPO,
                "--state",
                "open",
                "--json",
                "number,title,headRefName,body",
                "--limit",
                "200",
            ],
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        print(f"gh pr list failed: {exc}", file=sys.stderr)
        return 1

    findings: list[str] = []
    for pr in json.loads(raw):
        surface = "\n".join(
            [
                str(pr.get("title") or ""),
                str(pr.get("headRefName") or ""),
                str(pr.get("body") or ""),
            ]
        )
        for term in TERMS:
            match = term.search(surface)
            if match:
                findings.append(f"PR #{pr.get('number')}: matched {match.group(0)!r}")

    if findings:
        print("Open PR boundary violations:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
