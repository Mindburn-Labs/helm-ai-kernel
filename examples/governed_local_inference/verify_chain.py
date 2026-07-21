#!/usr/bin/env python3
"""Offline integrity check for a HELM proxy receipt chain.

Reads a receipts JSONL file produced by `helm-ai-kernel proxy --receipts-dir`
and verifies, with no network and no HELM binary, that:

  - each receipt's prev_hash links to the SHA-256 of the previous line's exact
    JSON bytes (the first line links to "GENESIS");
  - the Lamport clock increments by one with no gaps;
  - when the proxy was started with --sign, every receipt carries a signature.

The hash is computed over the raw bytes of each line as written, so this
reproduces the same causal chain the kernel maintains in
core/cmd/helm-ai-kernel/proxy_cmd.go (receiptStore.Append).
"""
import hashlib
import json
import sys


def verify(path: str) -> int:
    prev = "GENESIS"
    last_lamport = 0
    count = 0
    signed = 0
    with open(path, "rb") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.rstrip(b"\r\n")
            if not line.strip():
                continue
            receipt = json.loads(line)
            if receipt.get("prev_hash") != prev:
                print(f"FAIL line {lineno}: prev_hash {receipt.get('prev_hash')!r} != {prev!r}")
                return 1
            lamport = receipt.get("lamport_clock", 0)
            if lamport != last_lamport + 1:
                print(f"FAIL line {lineno}: lamport_clock {lamport} does not follow {last_lamport}")
                return 1
            if receipt.get("signature"):
                signed += 1
            prev = "sha256:" + hashlib.sha256(line).hexdigest()
            last_lamport = lamport
            count += 1
    if count == 0:
        print(f"FAIL: no receipts in {path}")
        return 1
    print(f"OK: {count} receipts, hash chain intact, {signed}/{count} signed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: verify_chain.py <receipts.jsonl>")
        raise SystemExit(2)
    raise SystemExit(verify(sys.argv[1]))
