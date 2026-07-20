#!/usr/bin/env python3
"""Independent approval dispatch-admission verifier.

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


def reseal_admission(admission):
    unsigned = dict(admission)
    unsigned.pop("admission_hash", None)
    admission["admission_hash"] = sha256_ref(canonical_json(unsigned).encode("utf-8"))


def verify_consumption_binding(admission, consumption):
    verify_connector_authority(consumption["connector_authority"], consumption)
    claimed_consumption_hash = consumption.get("consumption_hash")
    prefixed_bytes(claimed_consumption_hash, "sha256:", 32)
    unsigned_consumption = dict(consumption)
    unsigned_consumption.pop("consumption_hash")
    if sha256_ref(canonical_json(unsigned_consumption).encode("utf-8")) != claimed_consumption_hash:
        raise VectorError("consumption_binding_rejected", "consumption integrity mismatch")

    exact_fields = (
        ("approval_id", "approval_id"),
        ("grant_id", "grant_id"),
        ("grant_hash", "grant_hash"),
        ("consumption_hash", "consumption_hash"),
        ("tenant_id", "tenant_id"),
        ("workspace_id", "workspace_id"),
        ("audience", "audience"),
        ("admitted_by", "consumed_by"),
        ("effect_hash", "effect_hash"),
        ("action", "action"),
        ("kernel_trust_root_id", "kernel_trust_root_id"),
        ("signing_key_ref", "signing_key_ref"),
    )
    for admission_field, consumption_field in exact_fields:
        if admission[admission_field] != consumption[consumption_field]:
            raise VectorError("consumption_binding_rejected", f"{admission_field} mismatch")
    if admission["connector_authority"] != consumption["connector_authority"]:
        raise VectorError("consumption_binding_rejected", "connector authority mismatch")
    if (
        parse_time(admission["issued_at"]) < parse_time(consumption["consumed_at"])
        or parse_time(admission["issued_at"]) < parse_time(consumption["grant_issued_at"])
        or parse_time(admission["expires_at"]) > parse_time(consumption["grant_expires_at"])
    ):
        raise VectorError("consumption_binding_rejected", "admission outside consumed grant lifetime")


def verify_vector(index, root, mutation=None):
    descriptor = index["admission"]
    admission, _ = load_canonical(root, descriptor)
    consumption, _ = load_canonical(root, index["consumption"])
    admission = copy.deepcopy(admission)
    signature_value = descriptor["signature"]
    verification_time = parse_time(index["verification_time"])

    if mutation == "set_attempt_id_to_attempt-b":
        admission["attempt_id"] = "attempt-b"
    elif mutation == "set_connector_authority_certification_hash_to_tampered":
        admission["connector_authority"]["certification_hash"] = "sha256:" + "9" * 64
    elif mutation == "set_consumption_hash_to_tampered_and_reseal":
        admission["consumption_hash"] = "sha256:" + "9" * 64
        reseal_admission(admission)
    elif mutation == "set_verification_time_to_expires_at":
        verification_time = parse_time(admission["expires_at"])
    elif mutation == "flip_signature_last_bit":
        signature_value = flipped_signature(signature_value)
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    if (
        admission["schema_version"] != "approval-dispatch-admission.v1"
        or admission["contract_version"] != "2026-07-17.1"
        or admission["coverage"] != "new_governed_dispatches_only"
        or admission["state"] != "NOT_STARTED"
    ):
        raise VectorError("contract_mismatch", "unsupported dispatch admission contract")
    if admission["action"] not in ("install", "upgrade", "uninstall", "rollback"):
        raise VectorError("contract_mismatch", "unsupported pack lifecycle action")
    verify_connector_authority(admission["connector_authority"], consumption)
    verify_consumption_binding(admission, consumption)

    issued_at = parse_time(admission["issued_at"])
    expires_at = parse_time(admission["expires_at"])
    if expires_at <= issued_at or (expires_at - issued_at).total_seconds() > 60:
        raise VectorError("inactive_admission", "invalid admission lifetime")
    if verification_time < issued_at or verification_time >= expires_at:
        raise VectorError("inactive_admission", "admission is not live")

    claimed_hash = admission.pop("admission_hash")
    actual_hash = sha256_ref(canonical_json(admission).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("hash_mismatch", f"admission hash {actual_hash} != {claimed_hash}")

    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": "ed25519",
        "admission_hash": claimed_hash,
        "contract_version": admission["contract_version"],
        "domain": "HELM/ApprovalDispatchAdmissionSignature/v1",
        "kernel_trust_root_id": admission["kernel_trust_root_id"],
        "signing_key_ref": admission["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("signature_rejected", "dispatch admission signing payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("signature_rejected", "dispatch admission signature rejected")


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index["schema_version"] != "approval-dispatch-admission-vectors.v1" or index["contract_version"] != "2026-07-17.1":
        raise SystemExit("unsupported approval dispatch admission vector contract")
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
        "verified approval dispatch admission vector: "
        f"1 positive, {len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
