"""Read the local Console sidecar archive and metadata formats."""

from __future__ import annotations

import gzip
import json
import re
import stat
import tarfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any

HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SHA_40 = re.compile(r"^[0-9a-f]{40}$")
SAFE_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def reject(message: str) -> None:
    raise ValueError(message)


def require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        reject(f"{label} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected {', '.join(unexpected)}")
        reject(f"{label} has invalid fields: {'; '.join(details)}")
    return value


def require_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX_64.fullmatch(value):
        reject(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA_40.fullmatch(value):
        reject(f"{label} must be a full 40-character lowercase commit SHA")
    return value


def require_safe_file_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SAFE_FILE_NAME.fullmatch(value):
        reject(f"{label} must be a safe basename")
    return value


def require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        reject(f"{label} must be a non-empty string")
    return value


def require_runtime_value(value: Any, label: str) -> str:
    value = require_nonempty_string(value, label)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        reject(f"{label} must be a trimmed string no longer than 512 bytes")
    if value != value.strip() or len(encoded) > 512:
        reject(f"{label} must be a trimmed string no longer than 512 bytes")
    if any(unicodedata.category(character) == "Cc" for character in value):
        reject(f"{label} must not contain control characters")
    return value


def require_regular_file(path: Path, label: str) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        reject(f"{label} is missing: {path}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        reject(f"{label} must be a regular non-symlink file: {path}")


def require_file_size_at_most(path: Path, label: str, max_bytes: int) -> None:
    require_regular_file(path, label)
    try:
        size = path.stat().st_size
    except OSError as exc:
        reject(f"cannot inspect {label}: {exc}")
    if size < 0 or size > max_bytes:
        reject(f"{label} exceeds the validation limit")


def verify_gzip_stream(path: Path, label: str) -> None:
    """Drain a bounded gzip stream so its trailer and trailing bytes are valid."""
    try:
        with path.open("rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as compressed:
            while compressed.read(1024 * 1024):
                pass
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        reject(f"{label} gzip stream is invalid: {exc}")


def archive_member_is_directory(member: tarfile.TarInfo) -> bool:
    """Accept exactly the tar member forms the local launcher accepts."""
    if member.type == tarfile.DIRTYPE:
        if member.linkname:
            reject("archive directory has unsupported link metadata")
        return True
    if member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE} or member.linkname:
        reject("archive member is unsupported by the runtime")
    return False


def read_json(path: Path, label: str) -> dict[str, Any]:
    require_regular_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        reject(f"{label} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        reject(f"{label} must be a JSON object")
    return value


def safe_archive_path(name: str, *, directory: bool = False) -> str:
    """Return a canonical member name without weakening tar path rules.

    GNU tar emits directory members as ``root/`` while PurePosixPath renders
    that same canonical path as ``root``.  Accept that one representation only
    for actual directory members; files, links, and special members may never
    use a trailing slash.
    """
    if not name or "\\" in name:
        reject("archive member has an empty path")
    raw = name
    if raw.endswith("/"):
        if not directory:
            reject(f"non-directory archive member has a directory suffix: {name!r}")
        raw = raw[:-1]
    if not raw or raw == ".":
        reject(f"archive member has unsafe path: {name!r}")
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        reject(f"archive member has unsafe path: {name!r}")
    canonical = str(path)
    if canonical != raw:
        reject(f"archive member path is not canonical: {name!r}")
    return canonical


def verify_runtime(value: Any, target: dict[str, str]) -> dict[str, Any]:
    runtime = require_exact_keys(
        value,
        {"node", "bundled_node", "npm", "next", "platform", "libc"},
        "sidecar provenance.runtime",
    )
    runtime["node"] = require_runtime_value(runtime["node"], "sidecar provenance.runtime.node")
    runtime["npm"] = require_runtime_value(runtime["npm"], "sidecar provenance.runtime.npm")
    runtime["next"] = require_runtime_value(runtime["next"], "sidecar provenance.runtime.next")
    if not runtime["node"].startswith("v"):
        reject("sidecar provenance.runtime.node must be a versioned Node runtime")
    bundled_node = require_exact_keys(
        runtime["bundled_node"],
        {"executable", "license_notice"},
        "sidecar provenance.runtime.bundled_node",
    )
    if bundled_node != {"executable": "runtime/node/bin/node", "license_notice": "runtime/node/LICENSE"}:
        reject("sidecar provenance names an unexpected bundled Node runtime")
    platform = require_exact_keys(
        runtime["platform"],
        {"os", "arch", "target"},
        "sidecar provenance.runtime.platform",
    )
    if platform != {"os": target["os"], "arch": target["arch"], "target": f"{target['os']}-{target['arch']}"}:
        reject("sidecar provenance runtime platform does not match its target")
    libc = require_exact_keys(runtime["libc"], {"family", "version"}, "sidecar provenance.runtime.libc")
    expected_family = "libSystem" if target["os"] == "darwin" else "glibc"
    if libc["family"] != expected_family:
        reject("sidecar provenance runtime libc family does not match its target")
    if target["os"] == "darwin" and libc["version"] != "host-reported-unavailable":
        reject("Darwin sidecar provenance must use the declared libc version marker")
    require_runtime_value(libc["version"], "sidecar provenance.runtime.libc.version")
    return runtime


def read_json_from_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        reject(f"{label} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        reject(f"{label} must be an object")
    return value
