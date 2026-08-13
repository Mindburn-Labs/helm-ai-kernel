#!/usr/bin/env python3
"""Independent effect_permit.v1 verifier using only the Python stdlib.

quantum_posture: this pack checks classical Ed25519 test vectors only; the
effect_permit.v1 signing preimage is algorithm-neutral.
"""

import copy
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
APPROVAL_VERIFIER_ROOT = ROOT.parent / "approval"
sys.path.insert(0, str(APPROVAL_VERIFIER_ROOT))

from verify_approval_vectors import (  # noqa: E402
    VectorError,
    canonical_json,
    load_canonical,
    prefixed_bytes,
    verify_ed25519,
)


SIGNATURE_VERSION = "effect_permit.v1"
RFC3339_NANO = re.compile(
    r"^(?P<second>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)


def utc_rfc3339_nano(value):
    match = RFC3339_NANO.fullmatch(value)
    if match is None:
        raise VectorError("invalid_timestamp", f"invalid RFC3339Nano timestamp: {value}")
    zone = "+00:00" if match["zone"] == "Z" else match["zone"]
    try:
        instant = datetime.fromisoformat(match["second"] + zone).astimezone(timezone.utc)
    except ValueError as error:
        raise VectorError("invalid_timestamp", str(error)) from error
    fraction = (match["fraction"] or "").rstrip("0")
    return instant.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction else "") + "Z"


def signing_payload(permit, mutation=None):
    scope = permit["scope"]
    payload = {
        "signature_version": SIGNATURE_VERSION,
        "permit_id": permit["permit_id"],
        "intent_hash": permit["intent_hash"],
        "verdict_hash": permit["verdict_hash"],
        "plan_hash": permit.get("plan_hash", ""),
        "policy_hash": permit.get("policy_hash", ""),
        "effect_type": permit["effect_type"],
        "connector_id": permit["connector_id"],
        "scope": {
            "allowed_action": scope["allowed_action"],
            "allowed_params": scope.get("allowed_params", []),
            "deny_patterns": scope.get("deny_patterns", []),
        },
        "resource_ref": permit["resource_ref"],
        "expires_at": utc_rfc3339_nano(permit["expires_at"]),
        "single_use": permit["single_use"],
        "nonce": permit["nonce"],
        "issued_at": utc_rfc3339_nano(permit["issued_at"]),
        "issuer_id": permit["issuer_id"],
        "evidence_bindings": permit.get("evidence_bindings", {}),
    }
    if mutation == "build_payload_without_signature_version":
        payload.pop("signature_version")
    elif mutation == "build_payload_with_null_scope_lists":
        payload["scope"]["allowed_params"] = None
        payload["scope"]["deny_patterns"] = None
    elif mutation == "build_payload_without_utc_normalization":
        payload["issued_at"] = permit["issued_at"]
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)
    return payload


def verify_vector(index, vector, mutation=None):
    permit, _ = load_canonical(ROOT, vector["artifact"])
    expected_payload, expected_payload_text = load_canonical(ROOT, vector["signing_payload"])
    permit = copy.deepcopy(permit)
    signature_value = vector["signature"]

    if mutation == "remove_signature":
        permit.pop("signature", None)
    elif mutation == "uppercase_signature_hex":
        for offset, char in enumerate(permit["signature"]):
            if char in "abcdef":
                permit["signature"] = (
                    permit["signature"][:offset]
                    + char.upper()
                    + permit["signature"][offset + 1 :]
                )
                break
        else:
            raise VectorError("invalid_fixture", "signature contains no hex letter")
        signature_value = "ed25519:" + permit["signature"]
    elif mutation == "flip_signature_last_bit":
        signature = bytearray(prefixed_bytes("ed25519:" + permit["signature"], "ed25519:", 64))
        signature[-1] ^= 1
        permit["signature"] = signature.hex()
        signature_value = "ed25519:" + permit["signature"]
    elif mutation == "set_permit_id":
        permit["permit_id"] = "permit-tampered"
    elif mutation == "reverse_scope_allowed_params":
        permit["scope"]["allowed_params"].reverse()
    elif mutation not in (
        None,
        "build_payload_without_signature_version",
        "build_payload_with_null_scope_lists",
        "build_payload_without_utc_normalization",
    ):
        raise VectorError("unknown_mutation", mutation)

    raw_signature = permit.get("signature")
    if raw_signature is None:
        raise VectorError("permit_unsigned", "effect permit has no signature")
    if mutation is None and signature_value != "ed25519:" + raw_signature:
        raise VectorError("permit_signature_rejected", "detached signature does not match the permit")

    payload_mutation = mutation if mutation and mutation.startswith("build_payload_") else None
    actual_payload = signing_payload(permit, payload_mutation)
    actual_payload_text = canonical_json(actual_payload)
    if mutation is None and (actual_payload != expected_payload or actual_payload_text != expected_payload_text):
        raise VectorError("permit_signature_rejected", "published signing payload is not source-derived")

    public_key = prefixed_bytes(index["issuer_public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, actual_payload_text.encode("utf-8"), signature):
        raise VectorError("permit_signature_rejected", "effect permit signature rejected")


def main():
    index = json.loads((ROOT / "vectors.json").read_text(encoding="utf-8"))
    if (
        index.get("schema_version") != "effect-permit-vectors.v1"
        or index.get("signature_version") != SIGNATURE_VERSION
        or index.get("contract_version") != "2026-08-10"
        or index.get("status") != "final"
    ):
        raise SystemExit("unsupported effect permit vector contract")
    if index.get("quantum_posture") != "classical_ed25519_test_vectors":
        raise SystemExit("unexpected effect permit vector quantum posture")

    vectors = {vector["id"]: vector for vector in index.get("vectors", [])}
    negatives = index.get("negative_vectors", [])
    if len(vectors) != 2 or not negatives:
        raise SystemExit("effect permit vectors and negative mutations are required")

    for vector in vectors.values():
        verify_vector(index, vector)

    seen = set()
    for negative in negatives:
        if negative["id"] in seen:
            raise SystemExit(f"duplicate negative vector: {negative['id']}")
        seen.add(negative["id"])
        vector = vectors.get(negative["vector"])
        if vector is None:
            raise SystemExit(f"unknown vector: {negative['vector']}")
        try:
            verify_vector(index, vector, negative["mutation"])
        except VectorError as error:
            if error.code != negative["expected_error"]:
                raise SystemExit(
                    f"{negative['id']}: expected {negative['expected_error']}, got {error.code}: {error}"
                ) from error
        else:
            raise SystemExit(f"{negative['id']}: mutation unexpectedly verified")

    print(f"verified effect_permit.v1 vectors: {len(vectors)} positive, {len(negatives)} negative")


if __name__ == "__main__":
    main()
