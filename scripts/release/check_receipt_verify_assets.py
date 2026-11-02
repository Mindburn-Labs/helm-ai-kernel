#!/usr/bin/env python3
"""Check that a directory holds the standalone receipt_verify release assets.

Usage: check_receipt_verify_assets.py DIR [--root REPO_ROOT] [--allow-unexecuted]

DIR is either the build output (bin/) or the staged release directory
(dist/release-assets/). The check fails when

  * any of the five per-platform receipt_verify files is missing, empty or does
    not carry the executable header of its target platform, or
  * the binary built for this host does not behave like a verifier: it must
    accept the frozen receipt chain under its own key (exit 0, "valid": true),
    and it must reject the same chain under a wrong key and after a one-field
    tamper (exit 1, "valid": false).

The two rejection controls are what make the acceptance mean something. A
binary that exits 0 for everything would pass the positive check alone.

A host without a matching asset cannot run any of them. That is an error unless
--allow-unexecuted is passed, and the success line then says the run was not
executed, so a presence-only run is never reported as a full check.

quantum_posture: this check exercises the classical Ed25519 verifier on a
frozen fixture; it implements no cryptographic control and makes no
post-quantum claim.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
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

# Leading bytes of the executable format each target platform uses. Go builds
# 64-bit little-endian Mach-O, ELF and PE/COFF (MZ stub) for these targets.
MAGIC = {
    "linux": b"\x7fELF",
    "darwin": b"\xcf\xfa\xed\xfe",
    "windows": b"MZ",
}

FIXTURE = Path("core/pkg/receiptverify/testdata/frozen-chain-2026.json")
RUN_TIMEOUT_SECONDS = 60


def asset_platform(name: str) -> str:
    return name.split("-")[1]


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
        if path.stat().st_size == 0:
            errors.append(f"empty receipt_verify release asset: {name}")
            continue
        magic = MAGIC[asset_platform(name)]
        with path.open("rb") as handle:
            head = handle.read(len(magic))
        if head != magic:
            errors.append(
                f"{name} does not start with the {asset_platform(name)} executable header "
                f"(got {head.hex()}, want {magic.hex()})"
            )
    return errors


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

    try:
        code, payload, stderr = _run(binary, fixture, key)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"{name} could not be executed: {exc}"]
    if code != 0 or payload is None or payload.get("valid") is not True or not payload.get("receipts"):
        errors.append(
            f"{name} did not verify the frozen receipt chain under its own key "
            f"(exit {code}, valid={None if payload is None else payload.get('valid')!r}) {stderr}".rstrip()
        )

    # Control 1: the same chain under a different key must be rejected.
    wrong_key = f"{int(key[:2], 16) ^ 0x01:02x}{key[2:]}"
    code, payload, stderr = _run(binary, fixture, wrong_key)
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
        code, payload, stderr = _run(binary, tampered_path, key)
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
    if host_asset is None:
        if not allow_unexecuted:
            errors.append(
                f"no receipt_verify asset runs on this host ({system}/{machine}); "
                "pass --allow-unexecuted to accept a presence-only check"
            )
        summary = f"{len(ASSETS)} assets present, not executed (no asset for {system}/{machine})"
        return errors, summary
    if not errors:
        errors.extend(_check_behaviour(directory / host_asset, root))
    summary = f"{len(ASSETS)} assets present, {host_asset} verified the frozen chain and rejected a wrong key and a tampered receipt"
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
        help="accept a host that has no matching asset to run (presence-only check)",
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
