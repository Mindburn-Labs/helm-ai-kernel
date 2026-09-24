#!/usr/bin/env python3
"""Check that a kernel restart kept its receipts and its signing key.

The kind smoke used to compare the chart's signing Secret with itself across a
pod restart. A restart cannot change a Secret, so that check could not fail.
This one compares what the kernel serves:

  BEFORE  a receipt fetched by id before the restart
  AFTER   the same receipt id fetched after the restart
  ISSUED  a receipt the restarted kernel issued

AFTER must equal BEFORE (the receipt survived on the durable volume), and
ISSUED must carry the same public key as BEFORE (the restarted kernel signs
with the same key rather than a fresh one).

Usage: check_restart_persistence.py BEFORE AFTER ISSUED
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


class PersistenceError(Exception):
    """The restart lost a receipt or changed the signing key."""


def signing_keys(receipt: dict[str, Any], label: str) -> dict[str, str]:
    keys = receipt.get("public_key_set")
    if not isinstance(keys, dict) or not keys or not all(isinstance(v, str) and v for v in keys.values()):
        raise PersistenceError(f"{label} receipt carries no public_key_set, so its signer cannot be compared: {receipt}")
    if not receipt.get("signature"):
        raise PersistenceError(f"{label} receipt is unsigned: {receipt}")
    return keys


def check(before: dict[str, Any], after: dict[str, Any], issued: dict[str, Any]) -> None:
    receipt_id = before.get("receipt_id")
    if not receipt_id:
        raise PersistenceError(f"pre-restart receipt has no receipt_id: {before}")
    if after != before:
        raise PersistenceError(
            f"receipt {receipt_id} changed or was lost across the restart:\nbefore={before}\nafter={after}"
        )
    if issued.get("receipt_id") in (None, "", receipt_id):
        raise PersistenceError(f"expected a new receipt issued after the restart, got {issued}")
    before_keys = signing_keys(before, "pre-restart")
    issued_keys = signing_keys(issued, "post-restart")
    if issued_keys != before_keys:
        raise PersistenceError(
            f"signing key changed across the restart: before={before_keys} after={issued_keys}"
        )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    before, after, issued = (json.loads(Path(p).read_text(encoding="utf-8")) for p in argv[1:])
    try:
        check(before, after, issued)
    except PersistenceError as exc:
        print(f"::error::{exc}")
        return 1
    print(f"restart persistence: receipt {before['receipt_id']} unchanged, signer {sorted(before['public_key_set'])} unchanged")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
