#!/usr/bin/env python3
"""Independent effect-disposition command and Kernel receipt verifier.

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
MAX_SAFE_INTEGER = 2**53 - 1
ALLOWED_ACTIONS = {"HOLD", "RECONCILE_SOURCE", "REQUEST_CANCEL", "REQUEST_COMPENSATE"}
ALLOWED_RESERVATION_STATES = {"STARTED", "UNCERTAIN"}


def require_token(value, field):
    if not isinstance(value, str) or not value or len(value) > 512 or any(character.isspace() for character in value):
        raise VectorError("contract_rejected", f"invalid {field}")


def require_reason(value):
    if not isinstance(value, str) or not value or len(value) > 2048 or value != value.strip():
        raise VectorError("command_contract_rejected", "invalid reason")


def require_sha(value, field):
    try:
        prefixed_bytes(value, "sha256:", 32)
    except VectorError as error:
        raise VectorError("contract_rejected", f"invalid {field}") from error


def require_sequence(value, field):
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > MAX_SAFE_INTEGER:
        raise VectorError("contract_rejected", f"invalid {field}")


def parse_contract_time(value, field):
    if not isinstance(value, str) or not TIMESTAMP_RE.fullmatch(value):
        raise VectorError("contract_rejected", f"invalid {field}")
    return parse_time(value)


def reseal(artifact, hash_field):
    unsigned = dict(artifact)
    unsigned.pop(hash_field, None)
    artifact[hash_field] = sha256_ref(canonical_json(unsigned).encode("utf-8"))


def validate_chain(sequence, previous_hash, error_code):
    require_sequence(sequence, "disposition_sequence")
    if sequence == 1:
        if previous_hash is not None:
            raise VectorError(error_code, "first disposition claims a predecessor")
    else:
        try:
            require_sha(previous_hash, "previous_receipt_hash")
        except VectorError as error:
            raise VectorError(error_code, "successor disposition lacks predecessor") from error


def validate_command(command):
    if (
        command.get("schema_version") != "effect-disposition-command.v1"
        or command.get("contract_version") != "2026-07-18"
        or command.get("algorithm") != "ed25519"
    ):
        raise VectorError("command_contract_rejected", "unsupported disposition command contract")
    for field in (
        "command_id",
        "tenant_id",
        "workspace_id",
        "audience",
        "fence_command_id",
        "admission_id",
        "attempt_id",
        "connector_id",
        "connector_version",
        "connector_action",
        "connector_execution_ref",
        "intent_ref",
        "disposition_ref",
        "actor_id",
        "authority_id",
        "signing_key_ref",
    ):
        try:
            require_token(command.get(field), field)
        except VectorError as error:
            raise VectorError("command_contract_rejected", str(error)) from error
    for field in ("proof_session_ref", "effect_ref"):
        if field in command:
            try:
                require_token(command[field], field)
            except VectorError as error:
                raise VectorError("command_contract_rejected", str(error)) from error
    require_reason(command.get("reason"))
    for field in (
        "fence_command_hash",
        "fence_receipt_hash",
        "reservation_head_hash",
        "idempotency_key_hash",
        "effect_hash",
        "command_hash",
    ):
        try:
            require_sha(command.get(field), field)
        except VectorError as error:
            raise VectorError("command_contract_rejected", str(error)) from error
    validate_chain(command.get("disposition_sequence"), command.get("previous_receipt_hash"), "command_contract_rejected")
    for field in ("fence_epoch", "reservation_sequence"):
        try:
            require_sequence(command.get(field), field)
        except VectorError as error:
            raise VectorError("command_contract_rejected", str(error)) from error
    if command.get("reservation_state") not in ALLOWED_RESERVATION_STATES:
        raise VectorError("command_contract_rejected", "unsupported reservation state")
    if command.get("action") not in ALLOWED_ACTIONS:
        raise VectorError("command_contract_rejected", "unsupported action")
    try:
        issued_at = parse_contract_time(command.get("issued_at"), "issued_at")
        expires_at = parse_contract_time(command.get("expires_at"), "expires_at")
    except VectorError as error:
        raise VectorError("command_contract_rejected", str(error)) from error
    if expires_at <= issued_at or expires_at - issued_at > timedelta(minutes=10):
        raise VectorError("command_contract_rejected", "invalid command lifetime")
    return issued_at


def verify_command(index, root, command, envelope, signature_value):
    issued_at = validate_command(command)
    claimed_hash = command["command_hash"]
    unsigned = dict(command)
    unsigned.pop("command_hash")
    actual_hash = sha256_ref(canonical_json(unsigned).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("command_hash_mismatch", f"{actual_hash} != {claimed_hash}")
    if envelope.get("command") != command:
        raise VectorError("command_hash_mismatch", "envelope command mismatch")
    if envelope.get("signature") != signature_value.removeprefix("ed25519:"):
        raise VectorError("command_signature_rejected", "envelope signature mismatch")
    if (
        command["authority_id"] != "control-plane-a"
        or command["signing_key_ref"] != "kms://helm/control-plane/disposition/key-a"
        or command["audience"] != "packs.lifecycle"
    ):
        raise VectorError("command_trust_rejected", "command authority, key, or audience is not pinned")
    descriptor = index["command"]
    if issued_at < parse_time(descriptor["key_not_before"]) or issued_at >= parse_time(descriptor["key_not_after"]):
        raise VectorError("command_trust_rejected", "command outside key lifetime")
    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": command["algorithm"],
        "audience": command["audience"],
        "authority_id": command["authority_id"],
        "command_hash": claimed_hash,
        "contract_version": command["contract_version"],
        "domain": "HELM/EffectDispositionCommandSignature/v1",
        "signing_key_ref": command["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("command_signature_rejected", "command signing payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("command_signature_rejected", "command signature rejected")


def validate_receipt(receipt):
    if (
        receipt.get("schema_version") != "effect-disposition-receipt.v1"
        or receipt.get("contract_version") != "2026-07-18"
        or receipt.get("state") != "ACCEPTED"
        or receipt.get("execution_authority") != "NONE"
    ):
        raise VectorError("receipt_contract_rejected", "unsupported receipt contract or execution authority")
    for field in (
        "receipt_id",
        "command_id",
        "tenant_id",
        "workspace_id",
        "audience",
        "fence_command_id",
        "admission_id",
        "reservation_state",
        "action",
        "disposition_ref",
        "kernel_trust_root_id",
        "signing_key_ref",
        "accepted_by",
    ):
        try:
            require_token(receipt.get(field), field)
        except VectorError as error:
            raise VectorError("receipt_contract_rejected", str(error)) from error
    for field in (
        "command_hash",
        "fence_command_hash",
        "fence_receipt_hash",
        "reservation_head_hash",
        "receipt_hash",
    ):
        try:
            require_sha(receipt.get(field), field)
        except VectorError as error:
            raise VectorError("receipt_contract_rejected", str(error)) from error
    validate_chain(receipt.get("disposition_sequence"), receipt.get("previous_receipt_hash"), "receipt_contract_rejected")
    for field in ("fence_epoch", "reservation_sequence"):
        try:
            require_sequence(receipt.get(field), field)
        except VectorError as error:
            raise VectorError("receipt_contract_rejected", str(error)) from error
    if receipt.get("reservation_state") not in ALLOWED_RESERVATION_STATES:
        raise VectorError("receipt_contract_rejected", "unsupported reservation state")
    if receipt.get("action") not in ALLOWED_ACTIONS:
        raise VectorError("receipt_contract_rejected", "unsupported action")
    try:
        return parse_contract_time(receipt.get("accepted_at"), "accepted_at")
    except VectorError as error:
        raise VectorError("receipt_contract_rejected", str(error)) from error


def verify_receipt_binding(receipt, command):
    exact_fields = (
        "command_id",
        "command_hash",
        "disposition_sequence",
        "previous_receipt_hash",
        "tenant_id",
        "workspace_id",
        "audience",
        "fence_command_id",
        "fence_command_hash",
        "fence_epoch",
        "fence_receipt_hash",
        "admission_id",
        "reservation_sequence",
        "reservation_head_hash",
        "reservation_state",
        "action",
        "disposition_ref",
    )
    for field in exact_fields:
        if receipt.get(field) != command.get(field):
            raise VectorError("command_binding_rejected", f"{field} mismatch")


def verify_receipt(index, root, receipt, command, signature_value):
    accepted_at = validate_receipt(receipt)
    claimed_hash = receipt["receipt_hash"]
    unsigned = dict(receipt)
    unsigned.pop("receipt_hash")
    actual_hash = sha256_ref(canonical_json(unsigned).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("receipt_hash_mismatch", f"{actual_hash} != {claimed_hash}")
    verify_receipt_binding(receipt, command)
    if receipt["kernel_trust_root_id"] != "kernel-root-a" or receipt["signing_key_ref"] != "kms://helm/approval/key-a":
        raise VectorError("receipt_trust_rejected", "Kernel receipt trust root or key is not pinned")
    descriptor = index["receipt"]
    if accepted_at < parse_time(descriptor["key_not_before"]) or accepted_at >= parse_time(descriptor["key_not_after"]):
        raise VectorError("receipt_trust_rejected", "receipt outside key lifetime")
    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": "ed25519",
        "contract_version": receipt["contract_version"],
        "domain": "HELM/EffectDispositionReceiptSignature/v1",
        "kernel_trust_root_id": receipt["kernel_trust_root_id"],
        "receipt_hash": claimed_hash,
        "signing_key_ref": receipt["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("receipt_signature_rejected", "receipt signing payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("receipt_signature_rejected", "receipt signature rejected")


def verify_vector(index, root, mutation=None):
    command, _ = load_canonical(root, index["command"]["artifact"])
    envelope, _ = load_canonical(root, index["command"]["envelope"])
    receipt, _ = load_canonical(root, index["receipt"]["artifact"])
    command = copy.deepcopy(command)
    envelope = copy.deepcopy(envelope)
    receipt = copy.deepcopy(receipt)
    command_signature = index["command"]["signature"]
    receipt_signature = index["receipt"]["signature"]

    if mutation == "set_command_reservation_head_hash_to_tampered":
        command["reservation_head_hash"] = "sha256:" + "9" * 64
        envelope["command"]["reservation_head_hash"] = command["reservation_head_hash"]
    elif mutation == "flip_command_signature_last_bit":
        command_signature = flipped_signature(command_signature)
    elif mutation == "set_command_authority_id_to_other_and_reseal":
        command["authority_id"] = "control-plane-b"
        reseal(command, "command_hash")
        envelope["command"] = copy.deepcopy(command)
    elif mutation == "set_receipt_command_hash_to_other_and_reseal":
        receipt["command_hash"] = "sha256:" + "8" * 64
        reseal(receipt, "receipt_hash")
    elif mutation == "set_receipt_execution_authority_to_effect_and_reseal":
        receipt["execution_authority"] = "EFFECT"
        reseal(receipt, "receipt_hash")
    elif mutation == "flip_receipt_signature_last_bit":
        receipt_signature = flipped_signature(receipt_signature)
    elif mutation == "set_receipt_previous_hash_to_other_and_reseal":
        receipt["previous_receipt_hash"] = "sha256:" + "7" * 64
        reseal(receipt, "receipt_hash")
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    verify_command(index, root, command, envelope, command_signature)
    verify_receipt(index, root, receipt, command, receipt_signature)


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index.get("schema_version") != "effect-disposition-vectors.v1" or index.get("contract_version") != "2026-07-18":
        raise SystemExit("unsupported effect disposition vector contract")
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
        "verified effect disposition vectors: "
        f"2 signatures, {len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
