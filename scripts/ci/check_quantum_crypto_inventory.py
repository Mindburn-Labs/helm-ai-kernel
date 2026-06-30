#!/usr/bin/env python3
"""Require quantum-posture annotations on changed crypto-touching files.

quantum_posture: this checker is a guardrail, not a cryptographic control.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys


CRYPTO_RE = re.compile(
    r"crypto/(?:ed25519|rsa|ecdsa|tls|x509)|"
    r"\b(?:Ed25519|ed25519|RSA|ECDSA|X25519|ECDH|JWK|JWT|JWS|cosign|WireGuard|"
    r"ML-DSA|MLDSA|ML-KEM|Kyber|Dilithium|HELM_SIGNING_KEY)\b"
)


SKIP_PARTS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "testdata",
    "generated",
}


SKIP_SUFFIXES = {
    ".sum",
    ".lock",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".pdf",
    ".sig",
}


def changed_files(base: str) -> list[pathlib.Path]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{base}...HEAD"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return [pathlib.Path(line) for line in proc.stdout.splitlines() if line.strip()]


def should_skip(path: pathlib.Path) -> bool:
    if any(part in SKIP_PARTS for part in path.parts):
        return True
    if path.suffix in SKIP_SUFFIXES:
        return True
    if path.name.endswith((".gen.go", ".pb.go", ".pb.ts")):
        return True
    return False


def needs_annotation(path: pathlib.Path) -> bool:
    if should_skip(path) or not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return False
    return bool(CRYPTO_RE.search(text)) and "quantum_posture:" not in text


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", type=pathlib.Path)
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()

    paths = args.paths or changed_files(args.base)
    missing = [str(path) for path in paths if needs_annotation(path)]
    if missing:
        print("Missing quantum_posture annotations for crypto-touching files:", file=sys.stderr)
        for path in missing:
            print(f"  - {path}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
