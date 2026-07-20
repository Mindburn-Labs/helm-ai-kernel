#!/usr/bin/env python3
"""Independent connector acknowledgement and Kernel close verifier.

quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.
"""

import copy
import json
import re
import sys
from datetime import timedelta
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
    verify_ed25519,
)


TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$"
)


def require_token(value, field):
    if not isinstance(value, str) or not value or len(value) > 512 or any(character.isspace() for character in value):
        raise VectorError("contract_rejected", f"invalid {field}")


def require_sha(value, field):
    try:
        prefixed_bytes(value, "sha256:", 32)
    except VectorError as error:
        raise VectorError("contract_rejected", f"invalid {field}") from error


def parse_contract_time(value, field):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise VectorError("contract_rejected", f"invalid {field}")
    return parse_time(value)


def reseal(artifact, hash_field):
    unsigned = dict(artifact)
    unsigned.pop(hash_field, None)
    artifact[hash_field] = sha256_ref(canonical_json(unsigned).encode("utf-8"))


def validate_acknowledgement(acknowledgement):
    if (
        acknowledgement.get("schema_version") != "connector-effect-acknowledgement.v1"
        or acknowledgement.get("contract_version") != "2026-07-18"
        or acknowledgement.get("algorithm") != "ed25519"
    ):
        raise VectorError("acknowledgement_contract_rejected", "unsupported acknowledgement contract")
    for field in (
        "acknowledgement_id",
        "admission_id",
        "attempt_id",
        "tenant_id",
        "workspace_id",
        "audience",
        "connector_id",
        "connector_version",
        "connector_action",
        "connector_execution_ref",
        "intent_ref",
        "issuer_id",
        "signing_key_ref",
    ):
        require_token(acknowledgement.get(field), field)
    if "proof_session_ref" in acknowledgement:
        require_token(acknowledgement["proof_session_ref"], "proof_session_ref")
    if "reconciliation_ref" in acknowledgement:
        require_token(acknowledgement["reconciliation_ref"], "reconciliation_ref")
    for field in ("idempotency_key_hash", "effect_hash", "response_hash", "acknowledgement_hash"):
        require_sha(acknowledgement.get(field), field)
    if "disposition_receipt_hash" in acknowledgement:
        require_sha(acknowledgement["disposition_receipt_hash"], "disposition_receipt_hash")
    outcome = acknowledgement.get("outcome")
    if outcome == "APPLIED":
        require_token(acknowledgement.get("effect_ref"), "effect_ref")
    elif outcome == "NOT_APPLIED":
        if "effect_ref" in acknowledgement:
            raise VectorError("acknowledgement_contract_rejected", "NOT_APPLIED claims effect_ref")
    else:
        raise VectorError("acknowledgement_contract_rejected", "unsupported outcome")
    return parse_contract_time(acknowledgement.get("observed_at"), "observed_at")


def verify_acknowledgement(index, root, acknowledgement, envelope, signature_value):
    observed_at = validate_acknowledgement(acknowledgement)
    claimed_hash = acknowledgement["acknowledgement_hash"]
    unsigned = dict(acknowledgement)
    unsigned.pop("acknowledgement_hash")
    actual_hash = sha256_ref(canonical_json(unsigned).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("acknowledgement_hash_mismatch", f"{actual_hash} != {claimed_hash}")
    if envelope.get("acknowledgement") != acknowledgement:
        raise VectorError("acknowledgement_hash_mismatch", "envelope acknowledgement mismatch")
    if envelope.get("signature") != signature_value.removeprefix("ed25519:"):
        raise VectorError("acknowledgement_signature_rejected", "envelope signature mismatch")
    if acknowledgement["issuer_id"] != "publisher-a" or acknowledgement["signing_key_ref"] != "kms://helm/connector-ack/key-a":
        raise VectorError("acknowledgement_trust_rejected", "acknowledgement issuer or key is not pinned")
    descriptor = index["acknowledgement"]
    if observed_at < parse_time(descriptor["key_not_before"]) or observed_at >= parse_time(descriptor["key_not_after"]):
        raise VectorError("acknowledgement_trust_rejected", "acknowledgement outside key lifetime")
    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "acknowledgement_hash": claimed_hash,
        "algorithm": acknowledgement["algorithm"],
        "connector_id": acknowledgement["connector_id"],
        "connector_version": acknowledgement["connector_version"],
        "contract_version": acknowledgement["contract_version"],
        "domain": "HELM/ConnectorEffectAcknowledgementSignature/v1",
        "issuer_id": acknowledgement["issuer_id"],
        "signing_key_ref": acknowledgement["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("acknowledgement_signature_rejected", "acknowledgement payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("acknowledgement_signature_rejected", "acknowledgement signature rejected")


def validate_receipt(receipt):
    if (
        receipt.get("schema_version") != "effect-close-receipt.v1"
        or receipt.get("contract_version") != "2026-07-18"
        or receipt.get("state") != "COMPLETED"
    ):
        raise VectorError("receipt_contract_rejected", "unsupported close receipt contract")
    for field in (
        "close_id",
        "admission_id",
        "attempt_id",
        "tenant_id",
        "workspace_id",
        "audience",
        "connector_id",
        "connector_version",
        "connector_action",
        "connector_execution_ref",
        "intent_ref",
        "evidence_pack_ref",
        "kernel_trust_root_id",
        "signing_key_ref",
        "closed_by",
    ):
        require_token(receipt.get(field), field)
    if "proof_session_ref" in receipt:
        require_token(receipt["proof_session_ref"], "proof_session_ref")
    if receipt.get("prior_state") not in ("STARTED", "UNCERTAIN"):
        raise VectorError("receipt_contract_rejected", "unsupported prior state")
    if receipt["prior_state"] == "UNCERTAIN":
        try:
            require_token(receipt.get("reconciliation_ref"), "reconciliation_ref")
        except VectorError as error:
            raise VectorError("receipt_contract_rejected", "UNCERTAIN closure lacks reconciliation") from error
    sequence = receipt.get("reservation_sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1 or sequence > 9007199254740991:
        raise VectorError("receipt_contract_rejected", "invalid reservation sequence")
    for field in (
        "reservation_head_hash",
        "acknowledgement_hash",
        "idempotency_key_hash",
        "effect_hash",
        "response_hash",
        "evidence_pack_hash",
        "receipt_hash",
    ):
        require_sha(receipt.get(field), field)
    if "disposition_receipt_hash" in receipt:
        require_sha(receipt["disposition_receipt_hash"], "disposition_receipt_hash")
    if receipt.get("outcome") == "APPLIED":
        require_token(receipt.get("effect_ref"), "effect_ref")
    elif receipt.get("outcome") == "NOT_APPLIED":
        if "effect_ref" in receipt:
            raise VectorError("receipt_contract_rejected", "NOT_APPLIED receipt claims effect_ref")
    else:
        raise VectorError("receipt_contract_rejected", "unsupported outcome")
    return parse_contract_time(receipt.get("closed_at"), "closed_at")


def verify_receipt_binding(receipt, acknowledgement):
    exact_fields = (
        "admission_id",
        "attempt_id",
        "tenant_id",
        "workspace_id",
        "audience",
        "connector_id",
        "connector_version",
        "connector_action",
        "acknowledgement_hash",
        "outcome",
        "idempotency_key_hash",
        "effect_hash",
        "response_hash",
        "connector_execution_ref",
        "proof_session_ref",
        "intent_ref",
        "effect_ref",
        "reconciliation_ref",
        "disposition_receipt_hash",
    )
    for field in exact_fields:
        if receipt.get(field) != acknowledgement.get(field):
            raise VectorError("acknowledgement_binding_rejected", f"{field} mismatch")
    closed_at = parse_time(receipt["closed_at"])
    observed_at = parse_time(acknowledgement["observed_at"])
    if closed_at + timedelta(minutes=5) < observed_at:
        raise VectorError("acknowledgement_binding_rejected", "connector observation exceeds clock-skew window")


def verify_receipt(index, root, receipt, acknowledgement, signature_value):
    closed_at = validate_receipt(receipt)
    claimed_hash = receipt["receipt_hash"]
    unsigned = dict(receipt)
    unsigned.pop("receipt_hash")
    actual_hash = sha256_ref(canonical_json(unsigned).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("receipt_hash_mismatch", f"{actual_hash} != {claimed_hash}")
    verify_receipt_binding(receipt, acknowledgement)
    descriptor = index["receipt"]
    if closed_at < parse_time(descriptor["key_not_before"]) or closed_at >= parse_time(descriptor["key_not_after"]):
        raise VectorError("receipt_trust_rejected", "receipt outside key lifetime")
    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": "ed25519",
        "contract_version": receipt["contract_version"],
        "domain": "HELM/EffectCloseReceiptSignature/v1",
        "kernel_trust_root_id": receipt["kernel_trust_root_id"],
        "receipt_hash": claimed_hash,
        "signing_key_ref": receipt["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("receipt_signature_rejected", "receipt payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("receipt_signature_rejected", "receipt signature rejected")


def verify_vector(index, root, mutation=None):
    acknowledgement, _ = load_canonical(root, index["acknowledgement"]["artifact"])
    envelope, _ = load_canonical(root, index["acknowledgement"]["envelope"])
    receipt, _ = load_canonical(root, index["receipt"]["artifact"])
    acknowledgement = copy.deepcopy(acknowledgement)
    envelope = copy.deepcopy(envelope)
    receipt = copy.deepcopy(receipt)
    acknowledgement_signature = index["acknowledgement"]["signature"]
    receipt_signature = index["receipt"]["signature"]

    if mutation == "set_acknowledgement_response_hash_to_tampered":
        acknowledgement["response_hash"] = "sha256:" + "9" * 64
        envelope["acknowledgement"]["response_hash"] = acknowledgement["response_hash"]
    elif mutation == "flip_acknowledgement_signature_last_bit":
        acknowledgement_signature = flipped_signature(acknowledgement_signature)
    elif mutation == "set_acknowledgement_signing_key_ref_to_other_and_reseal":
        acknowledgement["signing_key_ref"] = "kms://helm/connector-ack/key-b"
        reseal(acknowledgement, "acknowledgement_hash")
        envelope["acknowledgement"] = copy.deepcopy(acknowledgement)
    elif mutation == "set_receipt_evidence_pack_hash_to_tampered":
        receipt["evidence_pack_hash"] = "sha256:" + "9" * 64
    elif mutation == "set_receipt_acknowledgement_hash_to_other_and_reseal":
        receipt["acknowledgement_hash"] = "sha256:" + "8" * 64
        reseal(receipt, "receipt_hash")
    elif mutation == "flip_receipt_signature_last_bit":
        receipt_signature = flipped_signature(receipt_signature)
    elif mutation == "set_receipt_disposition_hash_to_other_and_reseal":
        receipt["disposition_receipt_hash"] = "sha256:" + "7" * 64
        reseal(receipt, "receipt_hash")
    elif mutation == "remove_receipt_reconciliation_ref_and_reseal":
        receipt.pop("reconciliation_ref")
        reseal(receipt, "receipt_hash")
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    verify_acknowledgement(index, root, acknowledgement, envelope, acknowledgement_signature)
    verify_receipt(index, root, receipt, acknowledgement, receipt_signature)


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index.get("schema_version") != "effect-close-vectors.v1" or index.get("contract_version") != "2026-07-18":
        raise SystemExit("unsupported effect close vector contract")
    if index.get("quantum_posture") != "classical_ed25519_only" or not index.get("negative_vectors"):
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
        "verified effect close vectors: "
        f"2 signatures, {len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
