#!/usr/bin/env python3
"""Independent approval-grant consumption verifier.

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
    parse_time,
    prefixed_bytes,
    sha256_ref,
    verify_connector_authority,
    verify_ed25519,
)


def verify_vector(index, root, mutation=None):
    descriptor = index["consumption"]
    consumption, _ = load_canonical(root, descriptor)
    consumption = copy.deepcopy(consumption)
    signature_value = descriptor["signature"]

    if mutation == "set_consumed_by_to_data-plane-b":
        consumption["consumed_by"] = "spiffe://helm/data-plane-b"
    elif mutation == "set_connector_authority_certification_hash_to_tampered":
        consumption["connector_authority"]["certification_hash"] = "sha256:" + "9" * 64
    elif mutation == "set_consumed_at_to_grant_expiry":
        consumption["consumed_at"] = consumption["grant_expires_at"]
    elif mutation == "flip_signature_last_bit":
        signature_value = flipped_signature(signature_value)
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    if consumption["schema_version"] != "approval-grant-consumption.v1" or consumption["contract_version"] != "2026-07-17":
        raise VectorError("contract_mismatch", "unsupported grant consumption contract")
    if consumption["action"] not in ("install", "upgrade", "uninstall", "rollback"):
        raise VectorError("contract_mismatch", "unsupported pack lifecycle action")
    verify_connector_authority(consumption["connector_authority"], consumption)
    issued_at = parse_time(consumption["grant_issued_at"])
    expires_at = parse_time(consumption["grant_expires_at"])
    consumed_at = parse_time(consumption["consumed_at"])
    if consumed_at < issued_at or consumed_at >= expires_at:
        raise VectorError("inactive_consumption", "consumed_at is outside the grant lifetime")

    claimed_hash = consumption.pop("consumption_hash")
    actual_hash = sha256_ref(canonical_json(consumption).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("hash_mismatch", f"consumption hash {actual_hash} != {claimed_hash}")

    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": "ed25519",
        "consumption_hash": claimed_hash,
        "contract_version": consumption["contract_version"],
        "domain": "HELM/ApprovalGrantConsumptionSignature/v1",
        "kernel_trust_root_id": consumption["kernel_trust_root_id"],
        "signing_key_ref": consumption["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("signature_rejected", "consumption signing payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("signature_rejected", "consumption signature rejected")


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index["schema_version"] != "approval-grant-consumption-vectors.v1" or index["contract_version"] != "2026-07-17":
        raise SystemExit("unsupported approval grant consumption vector contract")
    if index["quantum_posture"] != "classical_ed25519_only" or not index["negative_vectors"]:
        raise SystemExit("unexpected vector posture or missing negative vectors")

    try:
        verify_vector(index, root)
        for negative in index["negative_vectors"]:
            try:
                verify_vector(index, root, negative["mutation"])
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

    print(
        "verified approval grant consumption vector: "
        f"1 positive, {len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
