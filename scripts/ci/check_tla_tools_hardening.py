#!/usr/bin/env python3
"""Static hardening checks for TLA tools download and execution."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PINNED_VERSION = "v1.8.0"
PINNED_SHA256 = "9e27b5e19a69ae1f56aabf8403a6ed5598dbfa6e638908e5278ac39736c1543d"
SHA256_RE = re.compile(r"\b[0-9a-f]{64}\b")


def fail(message: str) -> None:
    print(f"::error::{message}", file=sys.stderr)
    raise SystemExit(1)


def require(text: str, token: str, path: Path) -> None:
    if token not in text:
        fail(f"{path}: missing required TLA tools hardening token: {token}")


def forbid(text: str, token: str, path: Path) -> None:
    if token in text:
        fail(f"{path}: forbidden mutable or unchecked TLA tools token remains: {token}")


def check_downloader(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    require(text, f'DEFAULT_TLA_TOOLS_VERSION="{PINNED_VERSION}"', path)
    require(text, f'DEFAULT_TLA_TOOLS_SHA256="{PINNED_SHA256}"', path)
    require(text, "TLA_TOOLS_VERSION must be an immutable release tag", path)
    require(text, "TLA_TOOLS_JAR_URL must use HTTPS", path)
    require(text, "TLA_TOOLS_SHA256 must be a 64-character SHA-256 digest", path)
    require(text, "verify_jar", path)
    require(text, "sha256sum", path)
    require(text, "shasum -a 256", path)
    require(text, "tla2tools.jar SHA-256 mismatch", path)
    forbid(text, "releases/latest/download/tla2tools.jar", path)
    forbid(text, 'TLA_TOOLS_VERSION:-latest', path)


def check_workflow(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    require(text, "bash scripts/tla/download-tools.sh", path)
    require(text, f"TLA_TOOLS_VERSION: {PINNED_VERSION}", path)
    require(text, f"TLA_TOOLS_SHA256: {PINNED_SHA256}", path)
    if not SHA256_RE.search(text):
        fail(f"{path}: missing pinned TLA tools SHA-256")
    forbid(text, "releases/latest/download/tla2tools.jar", path)


def main() -> None:
    check_downloader(ROOT / "scripts/tla/download-tools.sh")
    check_workflow(ROOT / ".github/workflows/tla.yml")
    print("TLA tools hardening checks passed.")


if __name__ == "__main__":
    main()
