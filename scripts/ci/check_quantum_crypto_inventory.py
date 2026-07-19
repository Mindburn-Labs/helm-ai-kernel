#!/usr/bin/env python3
"""Require quantum-posture annotations on changed crypto-touching files.

quantum_posture: this checker is a guardrail, not a cryptographic control.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import os
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


def git_changed_files(args: list[str]) -> list[pathlib.Path] | None:
    proc = subprocess.run(
        args,
        text=True,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
    )
    if proc.returncode != 0:
        return None
    return [pathlib.Path(line) for line in proc.stdout.splitlines() if line.strip()]


def fetch_github_base_ref() -> None:
    base = os.environ.get("GITHUB_BASE_REF", "").strip()
    if not base:
        return
    subprocess.run(
        [
            "git",
            "fetch",
            "--no-tags",
            "--depth=100",
            "origin",
            f"+refs/heads/{base}:refs/remotes/origin/{base}",
        ],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )


def changed_files(base: str) -> list[pathlib.Path]:
    fetch_github_base_ref()

    refspecs: list[str] = []
    if base:
        refspecs.append(f"{base}...HEAD")

    github_base = os.environ.get("GITHUB_BASE_REF", "").strip()
    if github_base:
        refspecs.extend([f"origin/{github_base}...HEAD", f"{github_base}...HEAD"])
    refspecs.extend(["origin/main...HEAD", "main...HEAD", "HEAD~1...HEAD"])

    seen: set[str] = set()
    for refspec in refspecs:
        if refspec in seen:
            continue
        seen.add(refspec)
        paths = git_changed_files(["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", refspec])
        if paths is not None:
            return paths

    local: list[pathlib.Path] = []
    for args in (
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB"],
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    ):
        paths = git_changed_files(args)
        if paths:
            local.extend(paths)
    return local


def should_skip(path: pathlib.Path) -> bool:
    if any(part in SKIP_PARTS for part in path.parts):
        return True
    if path.suffix in SKIP_SUFFIXES:
        return True
    if path.name in {"TypesGen.java", "types.gen.ts", "types_gen.go", "types_gen.py", "types_gen.rs"}:
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
    if not CRYPTO_RE.search(text):
        return False
    if "quantum_posture:" in text:
        return False
    # Byte-exact reference-pack payloads -- the pinned `vectors.json` index and
    # the canonical `*.c14n.json` signing inputs it hash-pins -- carry live
    # Ed25519 signatures and are consumed as fixed bytes.  An inline annotation
    # would break the signature/digest, so keep them immutable and require the
    # local SOURCE-MANIFEST to carry the posture note instead.
    if path.name == "vectors.json" or path.name.endswith(".c14n.json"):
        manifest = path.with_name("SOURCE-MANIFEST.json")
        if manifest.is_file():
            try:
                return "quantum_posture" not in manifest.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                return True
    return True


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
