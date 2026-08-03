#!/usr/bin/env python3
"""Verify and stage a pinned Console local-sidecar closure for a Kernel release.

quantum_posture: validates classical SHA-256 and Cosign evidence only; it makes
no post-quantum assurance claim.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import unicodedata
from pathlib import Path, PurePosixPath
from typing import Any


MANIFEST_SCHEMA = "helm.console.local-sidecar.release-manifest.v1"
PINS_SCHEMA = "helm.console.local-sidecar.source-pins.v2"
COMPONENT = "app-helm-console"
CONSOLE_REPOSITORY = "Mindburn-Labs/app-helm-console"
MANIFEST_NAME = "helm-console-local-sidecar-release-manifest.json"
MANIFEST_BUNDLE_NAME = f"{MANIFEST_NAME}.cosign.bundle"
KERNEL_MANIFEST_BUNDLE_NAME = f"{MANIFEST_NAME}.kernel.cosign.bundle"
COSIGN_ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_IDENTITY = (
    "https://github.com/Mindburn-Labs/app-helm-console/"
    ".github/workflows/release-local-sidecar.yml@refs/heads/main"
)
TARGETS = ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64")
KERNEL_BINARY_NAMES = {target: f"helm-ai-kernel-{target}" for target in TARGETS}
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
SHA_40 = re.compile(r"^[0-9a-f]{40}$")
SAFE_FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
IMMUTABLE_WORKFLOW_REF = re.compile(r"^refs/tags/[0-9A-Za-z][-0-9A-Za-z._/+]*$")
INNER_PROVENANCE_SCHEMA = "helm.console.local-sidecar.provenance.v1"
UNSIGNED_INNER_SIGNATURE = "none; this unsigned local artifact has no release authority"
BUNDLE_MAX_BYTES = 512 * 1024 * 1024
INVENTORY_MAX_BYTES = 16 * 1024 * 1024
BUNDLE_HASH_SCOPE = (
    "sorted sha256 records for all closure payload files, including the bundled Node runtime; "
    "this binds the exact build and is not a cross-checkout byte-reproducibility claim"
)
BUILD_CONTRACT = {
    "api_mode": "kernel",
    "closure": ".next/standalone plus .next/static plus helm-local-sidecar.mjs plus runtime/node",
    "source_snapshot": "fresh git archive of recorded commit; npm ci and next build ran only inside the ephemeral snapshot",
    "environment": "strict platform allowlist plus fixed kernel build flags; dotenv inputs rejected",
}
INVENTORY_MAX_BYTES = 16 * 1024 * 1024
BUNDLE_MAX_BYTES = 512 * 1024 * 1024


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


def require_immutable_workflow_ref(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IMMUTABLE_WORKFLOW_REF.fullmatch(value):
        reject(f"{label} must be an immutable refs/tags/... reference")
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


def sha256_path(path: Path) -> str:
    require_regular_file(path, "artifact")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def locate_unique(root: Path, name: str, label: str) -> Path:
    require_safe_file_name(name, label)
    if root.is_symlink() or not root.is_dir():
        reject(f"artifact input directory must be a real directory: {root}")
    matches = [path for path in root.rglob(name) if path.name == name]
    if len(matches) != 1:
        reject(f"expected exactly one {label} named {name}, found {len(matches)}")
    require_regular_file(matches[0], label)
    return matches[0]


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


def parse_inventory(data: bytes) -> dict[str, str]:
    if not data or len(data) > INVENTORY_MAX_BYTES or data[-1] != 0x0A:
        reject("closure inventory is invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        reject(f"closure inventory is not UTF-8: {exc}")
    if "\r" in text:
        reject("closure inventory is invalid")
    lines = text[:-1].split("\n")
    entries: dict[str, str] = {}
    ordered: list[str] = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\s].*)", line)
        if match is None:
            reject(f"invalid closure inventory entry: {line!r}")
        digest, name = match.groups()
        safe_archive_path(name)
        if not (name.startswith("app/") or name in {"runtime/node/bin/node", "runtime/node/LICENSE"}):
            reject(f"closure inventory has an unsupported path: {name}")
        if name in entries:
            reject(f"duplicate closure inventory path: {name}")
        entries[name] = digest
        ordered.append(name)
    if not entries:
        reject("closure inventory is empty")
    if ordered != sorted(ordered):
        reject("closure inventory is not sorted")
    return entries


def require_source(value: Any, label: str) -> dict[str, str]:
    source = require_exact_keys(
        value,
        {"commit", "tree", "version", "package_lock_sha256"},
        label,
    )
    return {
        "commit": require_sha(source["commit"], f"{label}.commit"),
        "tree": require_sha(source["tree"], f"{label}.tree"),
        "version": require_semver(source["version"], f"{label}.version"),
        "package_lock_sha256": require_hex(source["package_lock_sha256"], f"{label}.package_lock_sha256"),
    }


def require_semver(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value):
        reject(f"{label} must be a plain semantic version")
    return value


def target_name(target: Any, label: str) -> tuple[str, dict[str, str]]:
    target_value = require_exact_keys(target, {"os", "arch"}, label)
    os_name = target_value["os"]
    arch = target_value["arch"]
    if os_name not in {"darwin", "linux"} or arch not in {"amd64", "arm64"}:
        reject(f"{label} has unsupported platform")
    return f"{os_name}-{arch}", {"os": os_name, "arch": arch}


def artifact_record(value: Any, label: str, expected_file: str) -> dict[str, str]:
    record = require_exact_keys(value, {"file", "sha256"}, label)
    file_name = require_safe_file_name(record["file"], f"{label}.file")
    if file_name != expected_file:
        reject(f"{label}.file must be {expected_file}, got {file_name}")
    return {"file": file_name, "sha256": require_hex(record["sha256"], f"{label}.sha256")}


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


def verify_provenance(
    external: Any,
    embedded: Any,
    archive_name: str,
    archive_digest: str,
    source: dict[str, str],
    target: dict[str, str],
    inner: dict[str, Any],
) -> None:
    external = require_exact_keys(
        external,
        {
            "schema", "target", "build", "source", "runtime", "bundle_sha256",
            "inventory", "bundle_hash_scope", "signature", "archive",
        },
        "external sidecar provenance",
    )
    embedded = require_exact_keys(
        embedded,
        {
            "schema", "target", "build", "source", "runtime", "bundle_sha256",
            "inventory", "bundle_hash_scope", "signature",
        },
        "embedded sidecar provenance",
    )
    external_core = {key: value for key, value in external.items() if key != "archive"}
    if embedded != external_core:
        reject("embedded sidecar provenance differs from the external provenance core")
    if external["schema"] != inner["provenance_schema"] or external["schema"] != INNER_PROVENANCE_SCHEMA:
        reject("sidecar provenance schema does not match the release manifest")
    if external["target"] != target:
        reject("sidecar provenance target does not match the release manifest")
    if external["source"] != source:
        reject("sidecar provenance source does not match the pinned release manifest")
    if external["build"] != BUILD_CONTRACT:
        reject("sidecar provenance build contract is unexpected")
    verify_runtime(external["runtime"], target)
    if external["inventory"] != "INVENTORY.sha256":
        reject("sidecar provenance does not name the closure inventory")
    if external["bundle_hash_scope"] != BUNDLE_HASH_SCOPE:
        reject("sidecar provenance has an unexpected bundle hash scope")
    if external["signature"] != inner["signature"]:
        reject("sidecar provenance signature state does not match the release manifest")
    archive = require_exact_keys(external["archive"], {"file", "sha256"}, "sidecar provenance.archive")
    if archive["file"] != archive_name or require_hex(archive["sha256"], "sidecar provenance.archive.sha256") != archive_digest:
        reject("sidecar provenance archive does not bind the released archive exactly")


def verify_archive(
    archive_path: Path,
    inventory_bytes: bytes,
    external_provenance_bytes: bytes,
    archive_digest: str,
    source: dict[str, str],
    target: dict[str, str],
    inner: dict[str, Any],
) -> None:
    expected_root = f"helm-console-local-sidecar-{target['os']}-{target['arch']}"
    require_file_size_at_most(archive_path, "sidecar archive", BUNDLE_MAX_BYTES)
    verify_gzip_stream(archive_path, "sidecar archive")
    try:
        archive = tarfile.open(archive_path, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        reject(f"unable to read sidecar archive {archive_path.name}: {exc}")

    files: dict[str, tuple[str, int]] = {}
    metadata: dict[str, bytes] = {}
    seen_members: set[str] = set()
    total = 0
    try:
        for member in archive.getmembers():
            is_directory = archive_member_is_directory(member)
            name = safe_archive_path(member.name, directory=is_directory)
            if name in seen_members:
                reject(f"archive contains duplicate member path: {member.name}")
            seen_members.add(name)
            parts = PurePosixPath(name).parts
            if parts[0] != expected_root:
                reject(f"archive member escapes expected closure root: {member.name}")
            if is_directory:
                continue
            relative = str(PurePosixPath(*parts[1:]))
            if not relative or relative in files:
                reject(f"archive contains duplicate or invalid payload path: {member.name}")
            if member.size < 0 or member.size > BUNDLE_MAX_BYTES or total > BUNDLE_MAX_BYTES - member.size:
                reject("archive payload exceeds the validation limit")
            total += member.size
            capture = relative in {"INVENTORY.sha256", "PROVENANCE.json"}
            if capture and member.size > INVENTORY_MAX_BYTES:
                reject("archive metadata exceeds the validation limit")
            handle = archive.extractfile(member)
            if handle is None:
                reject(f"archive cannot read payload: {member.name}")
            digest = hashlib.sha256()
            contents = bytearray() if capture else None
            remaining = member.size
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    reject(f"archive payload is truncated: {member.name}")
                digest.update(chunk)
                if contents is not None:
                    contents.extend(chunk)
                remaining -= len(chunk)
            files[relative] = (digest.hexdigest(), member.mode)
            if contents is not None:
                metadata[relative] = bytes(contents)
    finally:
        archive.close()

    for required in {"INVENTORY.sha256", "PROVENANCE.json", "app/helm-local-sidecar.mjs", "runtime/node/bin/node", "runtime/node/LICENSE"}:
        if required not in files:
            reject(f"archive is missing required closure file: {required}")
    if metadata["INVENTORY.sha256"] != inventory_bytes:
        reject("archive inventory differs from the released inventory artifact")
    if files["runtime/node/bin/node"][1] & 0o111 == 0:
        reject("bundled Node runtime is not executable")

    inventory = parse_inventory(inventory_bytes)
    payload = {name: digest for name, (digest, _) in files.items() if name not in {"INVENTORY.sha256", "PROVENANCE.json"}}
    if set(inventory) != set(payload):
        reject("archive payload does not exactly match its closure inventory")
    for name, expected_digest in inventory.items():
        if payload[name] != expected_digest:
            reject(f"closure inventory digest mismatch: {name}")

    bundle_sha256 = hashlib.sha256(inventory_bytes).hexdigest()
    if inner["bundle_sha256"] != bundle_sha256:
        reject("release manifest bundle hash does not match the archive inventory")
    verify_provenance(
        read_json_from_bytes(external_provenance_bytes, "external sidecar provenance"),
        read_json_from_bytes(metadata["PROVENANCE.json"], "embedded sidecar provenance"),
        archive_path.name,
        archive_digest,
        source,
        target,
        inner,
    )
    if read_json_from_bytes(external_provenance_bytes, "external sidecar provenance")["bundle_sha256"] != bundle_sha256:
        reject("sidecar provenance bundle hash does not match its inventory")


def read_json_from_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        reject(f"{label} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        reject(f"{label} must be an object")
    return value


def verify_target(root: Path, record: Any, source: dict[str, str]) -> tuple[str, list[Path]]:
    target_record = require_exact_keys(record, {"target", "inner_artifact", "artifacts"}, "target record")
    target, target_value = target_name(target_record["target"], "target record.target")
    inner = require_exact_keys(
        target_record["inner_artifact"],
        {"provenance_schema", "signature", "release_authority", "bundle_sha256"},
        f"target {target}.inner_artifact",
    )
    if inner["provenance_schema"] != INNER_PROVENANCE_SCHEMA:
        reject(f"target {target} has an unsupported inner provenance schema")
    if inner["signature"] != UNSIGNED_INNER_SIGNATURE:
        reject(f"target {target} has an unexpected unsigned inner artifact signature")
    if inner["release_authority"] is not False:
        reject(f"target {target} must not claim inner release authority")
    inner["bundle_sha256"] = require_hex(inner["bundle_sha256"], f"target {target}.inner_artifact.bundle_sha256")

    artifacts = require_exact_keys(
        target_record["artifacts"],
        {"archive", "archive_checksum", "inventory", "provenance"},
        f"target {target}.artifacts",
    )
    archive_name = f"helm-console-local-sidecar-{target}.tar.gz"
    records = {
        "archive": artifact_record(artifacts["archive"], f"target {target}.artifacts.archive", archive_name),
        "archive_checksum": artifact_record(artifacts["archive_checksum"], f"target {target}.artifacts.archive_checksum", f"{archive_name}.sha256"),
        "inventory": artifact_record(artifacts["inventory"], f"target {target}.artifacts.inventory", f"{archive_name}.inventory.sha256"),
        "provenance": artifact_record(artifacts["provenance"], f"target {target}.artifacts.provenance", f"{archive_name}.provenance.json"),
    }
    paths: dict[str, Path] = {}
    max_sizes = {
        "archive": BUNDLE_MAX_BYTES,
        "archive_checksum": INVENTORY_MAX_BYTES,
        "inventory": INVENTORY_MAX_BYTES,
        "provenance": INVENTORY_MAX_BYTES,
    }
    for kind, item in records.items():
        path = locate_unique(root, item["file"], f"target {target} {kind}")
        require_file_size_at_most(path, f"target {target} {kind}", max_sizes[kind])
        actual = sha256_path(path)
        if actual != item["sha256"]:
            reject(f"target {target} {kind} hash does not match the release manifest")
        paths[kind] = path

    archive_digest = sha256_path(paths["archive"])
    descriptor = paths["archive_checksum"].read_text(encoding="utf-8")
    if descriptor != f"{archive_digest}  {archive_name}\n":
        reject(f"target {target} archive checksum descriptor does not bind the archive exactly")
    verify_archive(
        paths["archive"],
        paths["inventory"].read_bytes(),
        paths["provenance"].read_bytes(),
        archive_digest,
        source,
        target_value,
        inner,
    )
    return target, [paths["archive"], paths["archive_checksum"], paths["inventory"], paths["provenance"]]


def load_pins(path: Path) -> list[dict[str, Any]]:
    payload = read_json(path, "source pins")
    pins = require_exact_keys(payload, {"schema", "pins"}, "source pins")
    if pins["schema"] != PINS_SCHEMA or not isinstance(pins["pins"], list):
        reject("source pins have an unsupported schema")
    return pins["pins"]


def resolve_pin(pins_path: Path, kernel_release: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for value in load_pins(pins_path):
        pin = require_exact_keys(value, {"kernel_release_version", "source_repository", "source", "workflow_ref"}, "source pin")
        if pin["kernel_release_version"] == kernel_release:
            matches.append(pin)
    if len(matches) != 1:
        reject(f"expected exactly one Console source pin for {kernel_release}, found {len(matches)}")
    pin = matches[0]
    if pin["source_repository"] != CONSOLE_REPOSITORY:
        reject("Console source pin names an unexpected repository")
    source = require_source(pin["source"], "source pin.source")
    workflow_ref = require_immutable_workflow_ref(pin["workflow_ref"], "source pin.workflow_ref")
    return {
        "kernel_release_version": kernel_release,
        "source_repository": CONSOLE_REPOSITORY,
        "source": source,
        "workflow_ref": workflow_ref,
    }


def verify_cosign(manifest: Path, bundle: Path) -> None:
    try:
        subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                COSIGN_IDENTITY,
                "--certificate-oidc-issuer",
                COSIGN_ISSUER,
                str(manifest),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        reject("cosign is required to verify the Console release manifest")
    except subprocess.CalledProcessError:
        reject("Console release manifest cosign verification failed")


def verify_kernel_cosign(manifest: Path, bundle: Path, kernel_release: str) -> None:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", kernel_release):
        reject(f"Kernel release must be an exact semantic tag: {kernel_release!r}")
    identity = (
        "https://github.com/Mindburn-Labs/helm-ai-kernel/"
        f".github/workflows/release.yml@refs/tags/{kernel_release}"
    )
    try:
        subprocess.run(
            [
                "cosign",
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity",
                identity,
                "--certificate-oidc-issuer",
                COSIGN_ISSUER,
                str(manifest),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        reject("cosign is required to verify the Kernel release manifest binding")
    except subprocess.CalledProcessError:
        reject("Kernel release manifest cosign verification failed")


def verify_release(
    root: Path,
    pins_path: Path,
    kernel_release: str,
    *,
    require_cosign: bool,
    expected_manifest_sha256: str | None = None,
) -> list[Path]:
    pin = resolve_pin(pins_path, kernel_release)
    manifest = locate_unique(root, MANIFEST_NAME, "Console aggregate release manifest")
    bundle = locate_unique(root, MANIFEST_BUNDLE_NAME, "Console aggregate manifest cosign bundle")
    manifest_sha256 = sha256_path(manifest)
    if expected_manifest_sha256 is not None:
        if require_hex(expected_manifest_sha256, "expected Console aggregate manifest SHA-256") != manifest_sha256:
            reject("Console aggregate release manifest SHA-256 does not match the expected compiled digest")
    payload = require_exact_keys(
        read_json(manifest, "Console aggregate release manifest"),
        {"schema", "component", "source_repository", "kernel_release_version", "source", "targets", "outer_signature"},
        "Console aggregate release manifest",
    )
    if payload["schema"] != MANIFEST_SCHEMA:
        reject("Console aggregate release manifest has an unsupported schema")
    if payload["component"] != COMPONENT or payload["source_repository"] != CONSOLE_REPOSITORY:
        reject("Console aggregate release manifest names an unexpected component")
    if payload["kernel_release_version"] != kernel_release:
        reject("Console aggregate release manifest is bound to a different Kernel release")
    source = require_source(payload["source"], "Console aggregate release manifest.source")
    if source != pin["source"]:
        reject("Console aggregate release manifest source does not match the checked-in source pin")
    outer = require_exact_keys(
        payload["outer_signature"],
        {"signed_file", "bundle", "issuer", "certificate_identity"},
        "Console aggregate release manifest.outer_signature",
    )
    if outer != {
        "signed_file": MANIFEST_NAME,
        "bundle": MANIFEST_BUNDLE_NAME,
        "issuer": COSIGN_ISSUER,
        "certificate_identity": COSIGN_IDENTITY,
    }:
        reject("Console aggregate release manifest has an unexpected outer signature contract")
    if require_cosign:
        verify_cosign(manifest, bundle)

    if not isinstance(payload["targets"], list):
        reject("Console aggregate release manifest targets must be a list")
    staged: list[Path] = [manifest, bundle]
    seen: set[str] = set()
    ordered_targets: list[str] = []
    for record in payload["targets"]:
        target, paths = verify_target(root, record, source)
        if target in seen:
            reject(f"Console aggregate release manifest has duplicate target: {target}")
        seen.add(target)
        ordered_targets.append(target)
        staged.extend(paths)
    if seen != set(TARGETS):
        reject(f"Console aggregate release manifest targets must be exactly: {', '.join(TARGETS)}")
    if tuple(ordered_targets) != TARGETS:
        reject(f"Console aggregate release manifest targets must be ordered exactly: {', '.join(TARGETS)}")
    return staged


def verify_kernel_release(
    root: Path,
    pins_path: Path,
    kernel_release: str,
    *,
    require_cosign: bool,
    expected_manifest_sha256: str | None,
) -> list[Path]:
    staged = verify_release(
        root,
        pins_path,
        kernel_release,
        require_cosign=require_cosign,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    kernel_bundle = locate_unique(root, KERNEL_MANIFEST_BUNDLE_NAME, "Kernel aggregate manifest cosign bundle")
    if kernel_bundle.stat().st_size == 0:
        reject("Kernel aggregate manifest cosign bundle must not be empty")
    if require_cosign:
        verify_kernel_cosign(staged[0], kernel_bundle, kernel_release)
    return [staged[0], staged[1], kernel_bundle, *staged[2:]]


def stage_release(
    root: Path,
    output_dir: Path,
    pins_path: Path,
    kernel_release: str,
    *,
    require_cosign: bool,
    expected_manifest_sha256: str | None,
) -> list[Path]:
    if expected_manifest_sha256 is None:
        reject("release staging requires the expected Console aggregate manifest SHA-256")
    staged = verify_kernel_release(
        root,
        pins_path,
        kernel_release,
        require_cosign=require_cosign,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    if output_dir.is_symlink():
        reject(f"release assets output directory must not be a symlink: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    copied: list[Path] = []
    for source in staged:
        destination = output_dir / source.name
        if destination.exists() and destination.is_symlink():
            reject(f"release asset destination must not be a symlink: {destination}")
        shutil.copy2(source, destination)
        copied.append(destination)
    return copied


def layout_archive_name(target: str) -> str:
    return f"helm-ai-kernel-{target}-console.tar.gz"


def layout_root_name(target: str) -> str:
    return f"helm-ai-kernel-{target}"


def tar_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(f"{name.rstrip('/')}/")
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    archive.addfile(info)


def tar_file(archive: tarfile.TarFile, name: str, source: Any, size: int, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o755 if mode & 0o111 else 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    archive.addfile(info, source)


def tar_path(archive: tarfile.TarFile, name: str, source: Path, mode: int | None = None) -> None:
    require_regular_file(source, f"release layout input {name}")
    with source.open("rb") as handle:
        tar_file(archive, name, handle, source.stat().st_size, source.stat().st_mode if mode is None else mode)


def tar_verified_target_tree(archive: tarfile.TarFile, source: Path, target: str, layout_root: str) -> None:
    expected_root = f"helm-console-local-sidecar-{target}"
    require_file_size_at_most(source, "verified sidecar archive", BUNDLE_MAX_BYTES)
    verify_gzip_stream(source, "verified sidecar archive")
    try:
        input_archive = tarfile.open(source, "r:gz")
    except (OSError, tarfile.TarError) as exc:
        reject(f"unable to read verified sidecar archive {source.name}: {exc}")
    try:
        members: list[tuple[str, tarfile.TarInfo]] = []
        seen: set[str] = set()
        total = 0
        for member in input_archive.getmembers():
            is_directory = archive_member_is_directory(member)
            name = safe_archive_path(member.name, directory=is_directory)
            if name in seen:
                reject(f"archive contains duplicate member path: {member.name}")
            seen.add(name)
            if PurePosixPath(name).parts[0] != expected_root:
                reject(f"archive member escapes expected closure root: {member.name}")
            if not is_directory:
                if member.size < 0 or member.size > BUNDLE_MAX_BYTES or total > BUNDLE_MAX_BYTES - member.size:
                    reject("archive payload exceeds the validation limit")
                total += member.size
            members.append((name, member))
        for name, member in sorted(members, key=lambda item: item[0]):
            destination = f"{layout_root}/console/{name}"
            if member.type == tarfile.DIRTYPE:
                tar_directory(archive, destination)
                continue
            handle = input_archive.extractfile(member)
            if handle is None:
                reject(f"archive cannot read payload: {member.name}")
            tar_file(archive, destination, handle, member.size, member.mode)
    finally:
        input_archive.close()


def package_release_layouts(
    root: Path,
    output_dir: Path,
    pins_path: Path,
    kernel_release: str,
    *,
    require_cosign: bool,
    expected_manifest_sha256: str | None,
) -> list[Path]:
    if expected_manifest_sha256 is None:
        reject("release layout packaging requires the expected Console aggregate manifest SHA-256")
    staged = verify_kernel_release(
        root,
        pins_path,
        kernel_release,
        require_cosign=require_cosign,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    if output_dir.is_symlink() or not output_dir.is_dir():
        reject(f"release layout output directory must be a real directory: {output_dir}")
    layout_paths: list[Path] = []
    for target in TARGETS:
        binary = root / KERNEL_BINARY_NAMES[target]
        require_regular_file(binary, f"Kernel binary for {target}")
        layout_root = layout_root_name(target)
        output = output_dir / layout_archive_name(target)
        if output.exists() and output.is_symlink():
            reject(f"release layout output must not be a symlink: {output}")
        temporary = output_dir / f".{output.name}.tmp"
        if temporary.exists() and temporary.is_symlink():
            reject(f"release layout temporary output must not be a symlink: {temporary}")
        with temporary.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                    tar_directory(archive, layout_root)
                    tar_path(archive, f"{layout_root}/helm-ai-kernel", binary, 0o755)
                    tar_directory(archive, f"{layout_root}/console")
                    for source in sorted(staged, key=lambda path: path.name):
                        tar_path(archive, f"{layout_root}/console/{source.name}", source, 0o644)
                    target_archive = next(path for path in staged if path.name == f"helm-console-local-sidecar-{target}.tar.gz")
                    tar_verified_target_tree(archive, target_archive, target, layout_root)
        os.replace(temporary, output)
        layout_paths.append(output)
    return layout_paths


def write_github_output(pin: dict[str, Any]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        reject("GITHUB_OUTPUT is required for --github-output")
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write(f"repository={pin['source_repository']}\n")
        handle.write(f"source_sha={pin['source']['commit']}\n")
        handle.write(f"workflow_ref={pin['workflow_ref']}\n")


def write_github_manifest_output(manifest_sha256: str) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        reject("GITHUB_OUTPUT is required for --github-output")
    with Path(output).open("a", encoding="utf-8") as handle:
        handle.write(f"manifest_sha256={manifest_sha256}\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pin_parser = commands.add_parser("pin", help="resolve an exact Console source pin")
    pin_parser.add_argument("--pins", type=Path, required=True)
    pin_parser.add_argument("--kernel-release", required=True)
    pin_parser.add_argument("--github-output", action="store_true")
    verify_parser = commands.add_parser("verify", help="verify a Console release input before Kernel assembly")
    verify_parser.add_argument("--input-dir", type=Path, required=True)
    verify_parser.add_argument("--pins", type=Path, required=True)
    verify_parser.add_argument("--kernel-release", required=True)
    verify_parser.add_argument("--expected-manifest-sha256")
    verify_parser.add_argument("--github-output", action="store_true")
    stage_parser = commands.add_parser("stage", help="stage a Console release input after digest binding")
    stage_parser.add_argument("--input-dir", type=Path, required=True)
    stage_parser.add_argument("--pins", type=Path, required=True)
    stage_parser.add_argument("--kernel-release", required=True)
    stage_parser.add_argument("--expected-manifest-sha256", required=True)
    stage_parser.add_argument("--output-dir", type=Path, required=True)
    layout_parser = commands.add_parser("layout", help="package standalone Kernel and Console layouts after digest binding")
    layout_parser.add_argument("--input-dir", type=Path, required=True)
    layout_parser.add_argument("--pins", type=Path, required=True)
    layout_parser.add_argument("--kernel-release", required=True)
    layout_parser.add_argument("--expected-manifest-sha256", required=True)
    layout_parser.add_argument("--output-dir", type=Path, required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "pin":
            pin = resolve_pin(args.pins, args.kernel_release)
            if args.github_output:
                write_github_output(pin)
            else:
                print(json.dumps(pin, sort_keys=True))
            return 0
        if args.command == "verify":
            staged = verify_release(
                args.input_dir,
                args.pins,
                args.kernel_release,
                require_cosign=True,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
            manifest_sha256 = sha256_path(locate_unique(args.input_dir, MANIFEST_NAME, "Console aggregate release manifest"))
            if args.github_output:
                write_github_manifest_output(manifest_sha256)
            print(json.dumps({"manifest_sha256": manifest_sha256, "verified": [path.name for path in staged]}, sort_keys=True))
            return 0
        if args.command == "stage":
            copied = stage_release(
                args.input_dir,
                args.output_dir,
                args.pins,
                args.kernel_release,
                require_cosign=True,
                expected_manifest_sha256=args.expected_manifest_sha256,
            )
            print(json.dumps({"manifest_sha256": args.expected_manifest_sha256, "staged": [path.name for path in copied]}, sort_keys=True))
            return 0
        layouts = package_release_layouts(
            args.input_dir,
            args.output_dir,
            args.pins,
            args.kernel_release,
            require_cosign=True,
            expected_manifest_sha256=args.expected_manifest_sha256,
        )
        print(json.dumps({"layouts": [path.name for path in layouts], "manifest_sha256": args.expected_manifest_sha256}, sort_keys=True))
        return 0
    except (OSError, ValueError, tarfile.TarError) as exc:
        print(f"::error file=scripts/release/console_local_sidecar.py::{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
