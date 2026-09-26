#!/usr/bin/env python3
"""Independent reference for approval digest v1
(docs/architecture/gateway-effect-api.md). gateway_contract_test.go runs it
and compares its output with the Go reference. Stdlib only.

quantum_posture: computes SHA-256 test vectors; signs or verifies nothing.
"""
import datetime
import hashlib
import json
import struct


def field(b: bytes) -> bytes:
    return struct.pack(">Q", len(b)) + b


def rfc3339_seconds(seconds: int) -> str:
    # Whole seconds, UTC, "Z" suffix: any fractional part is dropped.
    return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def approval_digest_v1(attempt_id, target_digest, argument_digest, quote, expires_seconds):
    m = field(b"helm.gateway.v1.approval-digest.v1")
    m += field(attempt_id.encode()) + field(target_digest) + field(argument_digest)
    ordered = sorted(quote, key=lambda q: q[0].encode())
    m += struct.pack(">Q", len(ordered))
    for unit, amount in ordered:
        m += field(unit.encode()) + struct.pack(">Q", amount)
    m += field(rfc3339_seconds(expires_seconds).encode())
    return hashlib.sha256(m).hexdigest()


def main():
    target = hashlib.sha256(b"github.com/Mindburn-Labs/example/pull/42").digest()
    args = hashlib.sha256(b'{"merge_method":"squash"}').digest()
    quote = [("count", 1), ("USD", 2500)]
    expires = int(datetime.datetime(2026, 9, 26, 12, 0, 0, tzinfo=datetime.timezone.utc).timestamp())
    # Sub-second input (…12:00:00.987654Z): the fraction is truncated, so the
    # digest equals the whole-second one.
    subsecond = datetime.datetime(2026, 9, 26, 12, 0, 0, 987654, tzinfo=datetime.timezone.utc)
    print(json.dumps({
        "whole_seconds": approval_digest_v1("0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", target, args, quote, expires),
        "subsecond_truncated": approval_digest_v1("0192f0c4-7a1e-7c3b-9d2a-5b8e4f1a2c3d", target, args, quote, int(subsecond.timestamp())),
        "expires_text": rfc3339_seconds(expires),
    }))


if __name__ == "__main__":
    main()
