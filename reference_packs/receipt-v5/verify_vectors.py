#!/usr/bin/env python3
"""Independent stdlib verifier for the receipt.v5 reference pack.

quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.
"""

import copy
import json
import sys
from pathlib import Path


APPROVAL_VERIFIER_ROOT = Path(__file__).resolve().parent.parent / "approval"
sys.path.insert(0, str(APPROVAL_VERIFIER_ROOT))

from verify_approval_vectors import (  # noqa: E402
    VectorError,
    canonical_json,
    flipped_signature,
    load_canonical,
    prefixed_bytes,
    verify_ed25519,
)


SIGNED_FIELDS = (
    "signature_version",
    "receipt_id",
    "decision_id",
    "effect_id",
    "status",
    "output_hash",
    "prev_hash",
    "lamport_clock",
    "args_hash",
    "verdict",
    "reason_code",
    "policy_hash",
    "session_id",
)


def check_interoperable(value, maximum, path="$"):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > maximum:
            raise VectorError("non_interoperable_number", f"{path} is outside +/-{maximum}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            check_interoperable(item, maximum, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            check_interoperable(item, maximum, f"{path}.{key}")
        return
    raise VectorError("non_interoperable_number", f"{path} has unsupported number type")


def verify_vector(index, vector, root, mutation=None):
    receipt, _ = load_canonical(root, vector["receipt"])
    receipt = copy.deepcopy(receipt)
    signature_value = vector["signature"]

    if mutation == "set_verdict_to_ALLOW":
        receipt["verdict"] = "ALLOW"
    elif mutation == "flip_signature_last_bit":
        signature_value = flipped_signature(signature_value)
    elif mutation == "set_lamport_clock_above_max_safe_integer":
        receipt["lamport_clock"] = index["canonicalization"]["max_safe_integer"] + 1
    elif mutation == "remove_empty_policy_hash":
        receipt.pop("policy_hash")
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    if receipt.get("signature_version") != "receipt.v5":
        raise VectorError("contract_mismatch", "signature_version must equal receipt.v5")
    missing = [field for field in SIGNED_FIELDS if field not in receipt]
    if missing:
        raise VectorError("contract_mismatch", f"missing signed members: {', '.join(missing)}")
    maximum = index["canonicalization"]["max_safe_integer"]
    check_interoperable(receipt, maximum)

    payload = {field: receipt[field] for field in SIGNED_FIELDS}
    payload_text = canonical_json(payload)
    public_key = prefixed_bytes(index["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("signature_rejected", f"{vector['id']}: Ed25519 signature rejected")

    expected_payload, expected_text = load_canonical(root, vector["signing_payload"])
    if payload != expected_payload or payload_text != expected_text:
        raise VectorError("payload_mismatch", f"{vector['id']}: derived signing payload differs")
    if signature_value != "ed25519:" + receipt["signature"]:
        raise VectorError("signature_rejected", f"{vector['id']}: detached signature differs")
    if receipt.get("key_id") != index["key_id"]:
        raise VectorError("contract_mismatch", f"{vector['id']}: key_id differs")
    if receipt.get("public_key_set", {}).get("ed25519") != index["public_key"].removeprefix("ed25519:"):
        raise VectorError("contract_mismatch", f"{vector['id']}: public key differs")


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index.get("schema_version") != "receipt-v5-vectors.v1" or index.get("signature_version") != "receipt.v5":
        raise SystemExit("unsupported receipt.v5 vector contract")
    if index.get("quantum_posture") != "classical_ed25519_only":
        raise SystemExit("unexpected receipt.v5 vector quantum posture")
    if index.get("canonicalization") != {
        "specification": "protocols/specs/rfc/canonical-json-v1.md",
        "profile": "interoperable_subset",
        "max_safe_integer": 9007199254740991,
    }:
        raise SystemExit("unexpected receipt.v5 canonicalization profile")

    vectors = {vector["id"]: vector for vector in index.get("vectors", [])}
    if len(vectors) != 3 or len(index.get("negative_vectors", [])) != 4:
        raise SystemExit("receipt.v5 pack requires 3 positives and 4 negative mutations")
    expected_canonical = {
        descriptor[key]["canonical"]
        for descriptor in vectors.values()
        for key in ("receipt", "signing_payload")
    }
    actual_canonical = {path.name for path in root.glob("*.c14n.json")}
    if actual_canonical != expected_canonical:
        raise SystemExit("receipt.v5 canonical file inventory differs from vectors.json")

    try:
        for vector in vectors.values():
            verify_vector(index, vector, root)
        for negative in index["negative_vectors"]:
            vector = vectors.get(negative["vector_id"])
            if vector is None:
                raise VectorError("contract_mismatch", f"unknown vector {negative['vector_id']}")
            try:
                verify_vector(index, vector, root, negative["mutation"])
            except VectorError as error:
                if error.code != negative["expected_error"]:
                    raise VectorError(
                        "negative_mismatch",
                        f"{negative['id']}: got {error.code}, want {negative['expected_error']}",
                    ) from error
            else:
                raise VectorError("negative_mismatch", f"{negative['id']}: mutation unexpectedly accepted")
    except VectorError as error:
        raise SystemExit(f"{error.code}: {error}") from error

    print("verified receipt.v5 vectors: 3 positive, 4 negative mutations, exact Go/Python parity")


if __name__ == "__main__":
    main()
