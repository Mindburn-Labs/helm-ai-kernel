#!/usr/bin/env python3
"""Check that a directory holds the standalone receipt_verify release assets.

Usage: check_receipt_verify_assets.py DIR [--root REPO_ROOT] [--allow-unexecuted]

DIR is either the build output (bin/) or the staged release directory
(dist/release-assets/). The check fails when

  * any of the five per-platform receipt_verify files is missing, smaller than
    MIN_ASSET_BYTES, or is not an executable for the operating system and CPU
    architecture its name states (ELF e_machine, Mach-O cputype, PE Machine), or
  * the binary built for this host does not behave like a verifier: it must
    accept the frozen receipt chain under its own key (exit 0, "valid": true),
    and it must reject the same chain under a wrong key and after a one-field
    tamper (exit 1, "valid": false).

The two rejection controls are what make the acceptance mean something. A
binary that exits 0 for everything would pass the positive check alone.

Only the host's asset can be executed; the other four are checked by size and
executable header only. The success line names which asset was executed and
which were header-checked, so a header check is never reported as a run.

A host without a matching asset cannot run any of them. That is an error unless
--allow-unexecuted is passed, and the success line then says none was executed.

quantum_posture: this check exercises the classical Ed25519 verifier on a
frozen fixture; it implements no cryptographic control and makes no
post-quantum claim.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

# The asset names users download. scripts/release/stage_release_assets.sh, the
# Makefile (release-binaries-reproducible) and scripts/ci/release_workflow_contract_test.py
# must name the same files; the contract test fails when they drift.
ASSETS = (
    "receipt_verify-linux-amd64",
    "receipt_verify-linux-arm64",
    "receipt_verify-darwin-amd64",
    "receipt_verify-darwin-arm64",
    "receipt_verify-windows-amd64.exe",
)

# The executable format each target OS uses, and the header field that names the
# CPU architecture. Go builds 64-bit little-endian ELF, Mach-O and PE/COFF for
# these targets, never a universal (fat) Mach-O.
FORMAT_OS = {"ELF": "linux", "Mach-O": "darwin", "PE": "windows"}
ELF_MACHINE = {62: "amd64", 183: "arm64"}  # EM_X86_64, EM_AARCH64
MACHO_CPUTYPE = {0x01000007: "amd64", 0x0100000C: "arm64"}  # CPU_TYPE_X86_64, CPU_TYPE_ARM64
PE_MACHINE = {0x8664: "amd64", 0xAA64: "arm64", 0x014C: "386"}  # IMAGE_FILE_MACHINE_*
HEADER_BYTES = 4096

# A stripped receipt_verify build is about 2.7 MiB on every target. Anything
# under 1 MiB is a stub, a truncated upload or a placeholder, not the verifier.
MIN_ASSET_BYTES = 1 << 20

FIXTURE = Path("core/pkg/receiptverify/testdata/frozen-chain-2026.json")
RUN_TIMEOUT_SECONDS = 60


def asset_target(name: str) -> tuple[str, str]:
    """Return the (GOOS, GOARCH) an asset name states."""
    stem = name[: -len(".exe")] if name.endswith(".exe") else name
    _, goos, goarch = stem.split("-")
    return goos, goarch


def executable_target(head: bytes) -> tuple[str, str] | str:
    """Return the (GOOS, GOARCH) an executable header declares, or why it has none."""
    if head[:4] == b"\x7fELF":
        if len(head) < 20 or head[4] != 2 or head[5] != 1:
            return "ELF header is not 64-bit little-endian"
        machine = struct.unpack_from("<H", head, 18)[0]
        return FORMAT_OS["ELF"], ELF_MACHINE.get(machine, f"unknown ELF machine {machine:#x}")
    if head[:4] == b"\xcf\xfa\xed\xfe":
        if len(head) < 8:
            return "Mach-O header is truncated"
        cputype = struct.unpack_from("<I", head, 4)[0]
        return FORMAT_OS["Mach-O"], MACHO_CPUTYPE.get(cputype, f"unknown Mach-O cputype {cputype:#x}")
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "universal (fat) Mach-O, not a single-architecture build"
    if head[:2] == b"MZ":
        if len(head) < 0x40:
            return "PE header is truncated"
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        if offset + 6 > len(head) or head[offset : offset + 4] != b"PE\x00\x00":
            return "MZ stub without a PE signature"
        machine = struct.unpack_from("<H", head, offset + 4)[0]
        return FORMAT_OS["PE"], PE_MACHINE.get(machine, f"unknown PE machine {machine:#x}")
    return f"no ELF, Mach-O or PE header (starts with {head[:4].hex()})"


def host_asset_name(system: str, machine: str) -> str | None:
    """Return the asset whose binary runs on this host, or None."""
    goos = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(system)
    goarch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }.get(machine.lower())
    if goos is None or goarch is None:
        return None
    suffix = ".exe" if goos == "windows" else ""
    name = f"receipt_verify-{goos}-{goarch}{suffix}"
    return name if name in ASSETS else None


def _run(binary: Path, receipt: Path, key: str) -> tuple[int, dict | None, str]:
    # A minimal environment: the verifier reads no configuration, so nothing
    # inherited from the caller can change its verdict.
    env = {"PATH": os.environ.get("PATH", ""), "HOME": tempfile.gettempdir()}
    proc = subprocess.run(
        [str(binary), "--receipt", str(receipt), "--key", key, "--json"],
        capture_output=True,
        text=True,
        timeout=RUN_TIMEOUT_SECONDS,
        env=env,
        check=False,
    )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = None
    if not isinstance(payload, dict):
        payload = None
    return proc.returncode, payload, proc.stderr.strip()


def _check_presence(directory: Path) -> list[str]:
    errors: list[str] = []
    for name in ASSETS:
        path = directory / name
        if not path.is_file():
            errors.append(f"missing receipt_verify release asset: {name}")
            continue
        size = path.stat().st_size
        if size == 0:
            errors.append(f"empty receipt_verify release asset: {name}")
            continue
        if size < MIN_ASSET_BYTES:
            errors.append(
                f"{name} is {size} bytes, smaller than the {MIN_ASSET_BYTES}-byte minimum for a receipt_verify build"
            )
            continue
        with path.open("rb") as handle:
            head = handle.read(HEADER_BYTES)
        goos, goarch = asset_target(name)
        found = executable_target(head)
        if isinstance(found, str):
            errors.append(f"{name} is not a {goos}/{goarch} executable: {found}")
        elif found != (goos, goarch):
            errors.append(
                f"{name} is a {found[0]}/{found[1]} executable, but its name says {goos}/{goarch}"
            )
    return errors


def _attempt(binary: Path, receipt: Path, key: str, step: str) -> tuple[int, dict | None, str] | str:
    """Run one verification, or return why it could not finish."""
    try:
        return _run(binary, receipt, key)
    except subprocess.TimeoutExpired:
        return f"{binary.name} did not finish within {RUN_TIMEOUT_SECONDS}s ({step})"
    except OSError as exc:
        return f"{binary.name} could not be executed ({step}): {exc}"


def _check_behaviour(binary: Path, root: Path) -> list[str]:
    fixture = root / FIXTURE
    if not fixture.is_file():
        return [f"receipt_verify smoke fixture is missing: {fixture}"]
    chain = json.loads(fixture.read_text(encoding="utf-8"))
    key = chain.get("public_key_hex")
    if not isinstance(key, str) or len(key) != 64:
        return [f"{FIXTURE} carries no 32-byte public_key_hex"]
    name = binary.name
    errors: list[str] = []

    result = _attempt(binary, fixture, key, "frozen chain, own key")
    if isinstance(result, str):
        return [result]
    code, payload, stderr = result
    if code != 0 or payload is None or payload.get("valid") is not True or not payload.get("receipts"):
        errors.append(
            f"{name} did not verify the frozen receipt chain under its own key "
            f"(exit {code}, valid={None if payload is None else payload.get('valid')!r}) {stderr}".rstrip()
        )

    # Control 1: the same chain under a different key must be rejected.
    wrong_key = f"{int(key[:2], 16) ^ 0x01:02x}{key[2:]}"
    result = _attempt(binary, fixture, wrong_key, "wrong-key control")
    if isinstance(result, str):
        return [*errors, result]
    code, payload, stderr = result
    if code != 1 or payload is None or payload.get("valid") is not False:
        errors.append(
            f"{name} did not reject the frozen chain under a wrong key "
            f"(exit {code}, want 1; valid={None if payload is None else payload.get('valid')!r}) {stderr}".rstrip()
        )

    # Control 2: the same chain with one signed field changed must be rejected.
    tampered = json.loads(json.dumps(chain))
    tampered["receipts"][0]["reason_code"] = tampered["receipts"][0]["reason_code"] + "_TAMPERED"
    with tempfile.TemporaryDirectory(prefix="receipt-verify-tamper.") as tmp:
        tampered_path = Path(tmp) / "tampered-chain.json"
        tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
        result = _attempt(binary, tampered_path, key, "tampered-receipt control")
    if isinstance(result, str):
        return [*errors, result]
    code, payload, stderr = result
    if code != 1 or payload is None or payload.get("valid") is not False:
        errors.append(
            f"{name} did not reject a tampered receipt "
            f"(exit {code}, want 1; valid={None if payload is None else payload.get('valid')!r}) {stderr}".rstrip()
        )
    return errors


def check(
    directory: Path,
    root: Path,
    *,
    allow_unexecuted: bool = False,
    host: tuple[str, str] | None = None,
) -> tuple[list[str], str]:
    """Return (errors, summary). Empty errors means the directory passed."""
    system, machine = host if host is not None else (platform.system(), platform.machine())
    errors = _check_presence(directory)
    host_asset = host_asset_name(system, machine)
    header_only = [name for name in ASSETS if name != host_asset]
    checked = f"header-checked only, not executed: {', '.join(header_only)}"
    if host_asset is None:
        if not allow_unexecuted:
            errors.append(
                f"no receipt_verify asset runs on this host ({system}/{machine}); "
                "pass --allow-unexecuted to accept a header-only check"
            )
        summary = f"{len(ASSETS)} assets present; none executed (no asset for {system}/{machine}); {checked}"
        return errors, summary
    if not errors:
        errors.extend(_check_behaviour(directory / host_asset, root))
    summary = (
        f"{len(ASSETS)} assets present; executed {host_asset}, which verified the frozen chain "
        f"and rejected a wrong key and a tampered receipt; {checked}"
    )
    return errors, summary


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("directory", type=Path, help="bin/ or dist/release-assets/")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="repository root that holds the smoke fixture (default: this checkout)",
    )
    parser.add_argument(
        "--allow-unexecuted",
        action="store_true",
        help="accept a host that has no matching asset to run (header-only check)",
    )
    args = parser.parse_args(argv)

    if not args.directory.is_dir():
        print(f"::error::receipt_verify asset directory not found: {args.directory}", file=sys.stderr)
        return 1
    errors, summary = check(args.directory, args.root, allow_unexecuted=args.allow_unexecuted)
    if errors:
        for error in errors:
            print(f"::error file=scripts/release/check_receipt_verify_assets.py::{error}", file=sys.stderr)
        return 1
    print(f"receipt_verify assets: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
