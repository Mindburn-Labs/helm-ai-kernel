#!/usr/bin/env python3
"""Scan evidence and logs for a secret without printing the secret.

The audit intentionally reports only finding types and file paths. It never
prints the secret value or the checked fragments.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def secret_needles(secret: str, min_fragment_length: int) -> list[tuple[str, bytes]]:
    values: list[tuple[str, str]] = [("full", secret)]
    if len(secret) >= min_fragment_length:
        values.append(("prefix", secret[:min_fragment_length]))
        values.append(("suffix", secret[-min_fragment_length:]))
        middle = max(0, (len(secret) - min_fragment_length) // 2)
        values.append(("middle", secret[middle : middle + min_fragment_length]))
    for part in secret.replace("_", "-").split("-"):
        if len(part) >= min_fragment_length:
            values.append(("component", part[:min_fragment_length]))

    seen: set[str] = set()
    needles: list[tuple[str, bytes]] = []
    for kind, value in values:
        if value and value not in seen:
            seen.add(value)
            needles.append((kind, value.encode("utf-8")))
    return needles


def iter_files(roots: list[Path]):
    for root in roots:
        if root.is_file():
            yield root
            continue
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.is_file():
                yield path


def scan(roots: list[Path], needles: list[tuple[str, bytes]]) -> tuple[list[dict[str, str]], int, int]:
    findings: list[dict[str, str]] = []
    scanned_files = 0
    scanned_bytes = 0
    for path in iter_files(roots):
        try:
            data = path.read_bytes()
        except OSError:
            continue
        scanned_files += 1
        scanned_bytes += len(data)
        for kind, needle in needles:
            if needle in data:
                findings.append({"path": str(path), "match_type": kind})
    return findings, scanned_files, scanned_bytes


def write_report(path: Path | None, report: dict) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        secret = "sk-test-abcdefghijklmnopqrstuvwxyz1234567890"
        (root / "clean.txt").write_text("no secret here\n", encoding="utf-8")
        findings, scanned_files, _ = scan([root], secret_needles(secret, 16))
        if findings or scanned_files != 1:
            print("self-test clean scan failed", file=sys.stderr)
            return 1
        (root / "leak.txt").write_text(f"token={secret[:16]}\n", encoding="utf-8")
        findings, _, _ = scan([root], secret_needles(secret, 16))
        if len(findings) != 1 or findings[0]["match_type"] != "prefix":
            print("self-test finding scan failed", file=sys.stderr)
            return 1
    print("secret-fragment-audit self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan files for secret values and fragments without printing them.")
    parser.add_argument("--secret-env", default="OPENROUTER_API_KEY", help="Environment variable containing the secret")
    parser.add_argument("--root", action="append", default=[], help="File or directory to scan; may be repeated")
    parser.add_argument("--json-out", help="Write redacted JSON report to this path")
    parser.add_argument("--min-fragment-length", type=int, default=16)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    secret = os.environ.get(args.secret_env, "")
    if len(secret) < args.min_fragment_length:
        print(f"secret-fragment-audit: {args.secret_env} is missing or too short for fragment audit", file=sys.stderr)
        return 2
    roots = [Path(item) for item in args.root]
    if not roots:
        print("secret-fragment-audit: at least one --root is required", file=sys.stderr)
        return 2

    findings, scanned_files, scanned_bytes = scan(roots, secret_needles(secret, args.min_fragment_length))
    report = {
        "schema_version": 1,
        "generated_at": now(),
        "secret_env": args.secret_env,
        "min_fragment_length": args.min_fragment_length,
        "roots": [str(root) for root in roots],
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "findings_count": len(findings),
        "findings": findings,
        "status": "PASS" if not findings else "FAIL",
    }
    write_report(Path(args.json_out) if args.json_out else None, report)
    if findings:
        print(f"secret-fragment-audit: FAIL, {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            print(f"  {finding['path']}: {finding['match_type']} match", file=sys.stderr)
        return 1
    print(f"secret-fragment-audit: PASS, scanned {scanned_files} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
