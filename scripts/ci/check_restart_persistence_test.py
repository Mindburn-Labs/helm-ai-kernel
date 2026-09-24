#!/usr/bin/env python3
"""Known-good and known-bad fixtures for the kind smoke's restart check.

quantum_posture: the ed25519 strings here are opaque fixture labels; nothing is
signed or verified, so no algorithm choice is made in this file.
"""

from __future__ import annotations

import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from check_restart_persistence import PersistenceError, check  # noqa: E402

KEY = {"ed25519": "11" * 32}
BEFORE = {
    "receipt_id": "rcpt-before",
    "decision_id": "dec-before",
    "status": "DENY",
    "signature": "ed25519:aa",
    "public_key_set": KEY,
}
ISSUED = {
    "receipt_id": "rcpt-after",
    "decision_id": "dec-after",
    "status": "DENY",
    "signature": "ed25519:bb",
    "public_key_set": dict(KEY),
}


class RestartPersistenceTest(unittest.TestCase):
    def test_same_receipt_and_same_key_pass(self) -> None:
        check(BEFORE, copy.deepcopy(BEFORE), ISSUED)

    def test_rotated_key_fails(self) -> None:
        rotated = {**ISSUED, "public_key_set": {"ed25519": "22" * 32}}
        with self.assertRaisesRegex(PersistenceError, "signing key changed"):
            check(BEFORE, copy.deepcopy(BEFORE), rotated)

    def test_lost_or_rewritten_receipt_fails(self) -> None:
        for after in ({}, {**BEFORE, "signature": "ed25519:cc"}, {**BEFORE, "receipt_id": "rcpt-other"}):
            with self.subTest(after=after), self.assertRaisesRegex(PersistenceError, "changed or was lost"):
                check(BEFORE, after, ISSUED)

    def test_missing_key_is_not_a_match(self) -> None:
        # Two receipts without keys compare equal; that must not read as "same signer".
        bare_before = {k: v for k, v in BEFORE.items() if k != "public_key_set"}
        bare_issued = {k: v for k, v in ISSUED.items() if k != "public_key_set"}
        with self.assertRaisesRegex(PersistenceError, "no public_key_set"):
            check(bare_before, copy.deepcopy(bare_before), bare_issued)

    def test_unsigned_receipt_fails(self) -> None:
        with self.assertRaisesRegex(PersistenceError, "unsigned"):
            check(BEFORE, copy.deepcopy(BEFORE), {**ISSUED, "signature": ""})

    def test_the_old_receipt_does_not_count_as_newly_issued(self) -> None:
        with self.assertRaisesRegex(PersistenceError, "new receipt"):
            check(BEFORE, copy.deepcopy(BEFORE), copy.deepcopy(BEFORE))


if __name__ == "__main__":
    unittest.main()
