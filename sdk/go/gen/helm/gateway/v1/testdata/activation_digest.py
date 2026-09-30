#!/usr/bin/env python3
"""Independent reference for activation digest v1
(docs/architecture/gateway-provisioning-api.md). authority_admin_contract_test.go
runs it and compares its output with the Go reference. Stdlib only.

quantum_posture: computes SHA-256 test vectors; signs or verifies nothing.
"""
import datetime
import hashlib
import json
import struct


def u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def field(b: bytes) -> bytes:
    return u64(len(b)) + b


def strings(values) -> bytes:
    # A count, then each entry length-prefixed, sorted by bytes, each once.
    ordered = sorted({v.encode() for v in values})
    return u64(len(ordered)) + b"".join(field(v) for v in ordered)


def optional(value) -> bytes:
    return b"\x00" if value is None else b"\x01" + u64(value)


def micros_text(seconds: int, nanos: int) -> str:
    # RFC 3339, UTC, exactly six fractional digits, truncated (not rounded).
    stamp = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S") + ".%06dZ" % (nanos // 1000)


def activation_digest_v1(holder, requested_by, terms, limits) -> str:
    m = field(b"helm.gateway.v1.mandate-activation-digest.v1")
    m += field(holder.encode()) + field(requested_by.encode())
    m += strings(terms["effect_types"])
    m += optional(terms.get("per_call_limit")) + optional(terms.get("approval_threshold"))
    m += field(micros_text(*terms["valid_from"]).encode()) + field(micros_text(*terms["valid_until"]).encode())
    m += strings(terms.get("targets", []))
    m += field(terms.get("condition", "").encode())
    m += strings(terms.get("approval_required", []))
    risks = sorted(terms.get("risk_classes", {}).items(), key=lambda kv: kv[0].encode())
    m += u64(len(risks)) + b"".join(field(k.encode()) + field(v.encode()) for k, v in risks)
    ordered = sorted(limits, key=lambda l: (l["unit"].encode(), l["measure"].encode(), l["window"].encode(), l["span"], l["value"]))
    m += u64(len(ordered))
    for l in ordered:
        m += field(l["unit"].encode()) + field(l["measure"].encode()) + field(l["window"].encode()) + u64(l["span"]) + u64(l["value"])
    return hashlib.sha256(m).hexdigest()


def utc(year, month, day, hour, minute, second, nanos=0):
    stamp = datetime.datetime(year, month, day, hour, minute, second, tzinfo=datetime.timezone.utc)
    return (int(stamp.timestamp()), nanos)


def vector():
    # The vector in docs/architecture/gateway-provisioning-api.md. Effect types,
    # targets and limits are given out of order on purpose, and valid_until
    # carries nanoseconds that the digest truncates to microseconds.
    terms = {
        "effect_types": ["github.repository.get", "github.branch.create_from_changes", "github.repository.get"],
        "approval_threshold": 0,
        "valid_from": utc(2026, 9, 30, 0, 0, 0),
        "valid_until": utc(2026, 10, 30, 12, 30, 45, 123456789),
        "targets": ["github.com/Mindburn-Labs/example", "github.com/Mindburn-Labs/other"],
        "condition": 'input.args.head.startsWith("helm/")',
        "approval_required": ["github.branch.create_from_changes"],
        "risk_classes": {"github.repository.get": "low", "github.branch.create_from_changes": "medium"},
    }
    limits = [
        {"unit": "usd_cents", "measure": "sum", "window": "month", "span": 1, "value": 50000},
        {"unit": "count", "measure": "count", "window": "day", "span": 1, "value": 20},
    ]
    return terms, limits


def main():
    terms, limits = vector()
    whole = activation_digest_v1("agent-a", "human-a", terms, limits)
    # The same request with valid_until at .123456 s is the same digest: the
    # remaining nanoseconds are truncated away.
    trimmed = dict(terms, valid_until=utc(2026, 10, 30, 12, 30, 45, 123456000))
    # Reordering effect types, targets and limits changes nothing.
    reordered_terms = dict(terms, effect_types=list(reversed(terms["effect_types"])), targets=list(reversed(terms["targets"])))
    print(json.dumps({
        "digest": whole,
        "truncated": activation_digest_v1("agent-a", "human-a", trimmed, limits),
        "reordered": activation_digest_v1("agent-a", "human-a", reordered_terms, list(reversed(limits))),
        "valid_until_text": micros_text(*terms["valid_until"]),
    }))


if __name__ == "__main__":
    main()
