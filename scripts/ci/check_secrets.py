#!/usr/bin/env python3
"""Lightweight tracked-file secret scan for CI quality gates."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAX_BYTES = 1_500_000
SKIP_SUFFIXES = {
    ".lock",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".tar",
    ".gz",
    ".zip",
}
SKIP_PATH_PARTS = {
    "node_modules",
    "dist",
    "build",
    "target",
    "bin",
    ".git",
}
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |)?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe-secret-key", re.compile(r"\bsk_(?:test|live)_[0-9a-zA-Z]{24,}\b")),
]


def is_known_fixture(rel: str, line: str, name: str) -> bool:
    stripped = line.strip()
    if name == "aws-access-key" and "EXAMPLE" in line:
        return True
    if name == "private-key":
        if rel.endswith("_test.go"):
            return True
        if '"-----BEGIN' in line or "`-----BEGIN" in line:
            return True
        if stripped.startswith("//"):
            return True
    return False


def tracked_files() -> list[str]:
    result = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def should_scan(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if any(part in SKIP_PATH_PARTS for part in rel.parts):
        return False
    if path.suffix.lower() in SKIP_SUFFIXES:
        return False
    try:
        return path.stat().st_size <= MAX_BYTES
    except FileNotFoundError:
        return False


def main() -> int:
    findings: list[str] = []
    scanned = 0
    for rel in tracked_files():
        path = ROOT / rel
        if not should_scan(path):
            continue
        scanned += 1
        text = path.read_text(errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            for name, pattern in PATTERNS:
                if pattern.search(line) and not is_known_fixture(rel, line, name):
                    findings.append(f"{rel}:{line_no}: matched {name}")

    if findings:
        print("Secret scan found potential secrets:")
        for finding in findings:
            print(f"- {finding}")
        return 1

    print(f"Secret scan passed: {scanned} tracked text files scanned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
