#!/usr/bin/env python3
"""Independent GeneratedSpec ceremony source-contract verifier.

This verifies deterministic fixture parity only. It does not prove a durable
store, runtime transport, Control Plane transition, or production authority.

quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.
"""

import copy
import json
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


HASH_FIELDS = (
    "generated_spec_hash",
    "execution_plan_hash",
    "plan_transaction_hash",
    "write_set_hash",
    "verification_scope_hash",
    "policy_envelope_hash",
    "authority_snapshot_hash",
)

# NOTE on nonce: challenge and grant carry deliberately independent fresh
# randomness — the challenge nonce is ceremony freshness, the grant nonce is
# single-use entropy for consumption. They are NOT field-equal by design, so
# nonce is absent from GRANT_BINDING_FIELDS. Nonce integrity is still bound
# transitively: nonce -> grant_hash (sealed content) -> grant signature, and
# the grant_nonce_tamper negative vector proves a resealed nonce swap fails
# signature verification.
GRANT_BINDING_FIELDS = (
    "approval_id",
    "tenant_id",
    "workspace_id",
    "audience",
    "generated_spec_id",
    "generated_spec_hash",
    "execution_plan_hash",
    "plan_transaction_hash",
    "write_set_hash",
    "verification_scope_hash",
    "policy_envelope_hash",
    "policy_version",
    "policy_epoch",
    "action",
    "requesting_principal_id",
    "authority_source",
    "authority_version",
    "authority_snapshot_hash",
    "server_identity",
)

CONSUMPTION_BINDING_FIELDS = (
    "approval_id",
    "grant_id",
    "grant_hash",
    "tenant_id",
    "workspace_id",
    "audience",
    "generated_spec_id",
    "generated_spec_hash",
    "execution_plan_hash",
    "plan_transaction_hash",
    "write_set_hash",
    "verification_scope_hash",
    "policy_envelope_hash",
    "policy_version",
    "policy_epoch",
    "action",
    "requesting_principal_id",
    "approver_principal_ids",
    "challenge_hash",
    "ceremony_hash",
    "signer_set_hash",
    "authority_source",
    "authority_version",
    "authority_snapshot_hash",
    "server_identity",
    "kernel_trust_root_id",
    "signing_key_ref",
)


def require_contract(value, domain, schema):
    if (
        value.get("domain") != domain
        or value.get("schema_version") != schema
        or value.get("contract_version") != "2026-07-22"
        or value.get("audience") != "generated-spec.approval"
        or value.get("action") != "approve_generated_spec"
    ):
        raise VectorError("contract_mismatch", "unsupported GeneratedSpec approval contract")


def require_hash(value, field, error_code):
    claimed = value.get(field)
    prefixed_bytes(claimed, "sha256:", 32)
    unsigned = dict(value)
    unsigned.pop(field, None)
    if sha256_ref(canonical_json(unsigned).encode("utf-8")) != claimed:
        raise VectorError(error_code, f"{field} does not match canonical content")


def require_token(value, field):
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise VectorError("contract_mismatch", f"{field} is required and must not contain whitespace")


def require_utc_time(value, field):
    try:
        parsed = parse_time(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise VectorError("contract_mismatch", f"{field} must be a timestamp") from error
    if parsed.utcoffset() != timedelta(0):
        raise VectorError("contract_mismatch", f"{field} must use UTC")
    return parsed


def require_nonce(value, field):
    if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
        raise VectorError("contract_mismatch", f"{field} must be 32 lowercase hexadecimal bytes")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError("contract_mismatch", f"{field} must be 32 lowercase hexadecimal bytes") from error
    if len(raw) != 32:
        raise VectorError("contract_mismatch", f"{field} must be 32 lowercase hexadecimal bytes")


def require_approvers(requester, approvers):
    if not isinstance(approvers, list) or not approvers or not all(isinstance(approver, str) for approver in approvers):
        raise VectorError("contract_mismatch", "grant approvers are invalid")
    if approvers != sorted(approvers):
        raise VectorError("contract_mismatch", "grant approvers must be sorted")
    for approver in approvers:
        require_token(approver, "approver_principal_ids")
    if requester in approvers:
        raise VectorError("contract_mismatch", "grant approvers are invalid")
    if len(set(approvers)) != len(approvers):
        raise VectorError("contract_mismatch", "grant approvers must be unique")


def verify_challenge(challenge):
    require_contract(
        challenge,
        "HELM/GeneratedSpecApprovalChallenge/v1",
        "generated-spec-approval-challenge.v1",
    )
    quorum = challenge.get("quorum")
    if not isinstance(quorum, int) or isinstance(quorum, bool) or quorum <= 0:
        raise VectorError("contract_mismatch", "challenge quorum must be a positive integer")
    for field in HASH_FIELDS:
        prefixed_bytes(challenge.get(field), "sha256:", 32)
    require_hash(challenge, "challenge_hash", "challenge_hash_mismatch")
    hold_started_at = require_utc_time(challenge.get("hold_started_at"), "hold_started_at")
    eligible_at = require_utc_time(challenge.get("eligible_at"), "eligible_at")
    issued_at = require_utc_time(challenge.get("issued_at"), "issued_at")
    expires_at = require_utc_time(challenge.get("expires_at"), "expires_at")
    if not hold_started_at < eligible_at <= issued_at < expires_at:
        raise VectorError("contract_mismatch", "challenge lifetime is invalid")
    require_nonce(challenge.get("nonce"), "challenge nonce")


def verify_grant(grant, challenge):
    require_contract(
        grant,
        "HELM/GeneratedSpecApprovalGrant/v1",
        "generated-spec-approval-grant.v1",
    )
    for field in HASH_FIELDS + ("challenge_hash", "ceremony_hash", "signer_set_hash"):
        prefixed_bytes(grant.get(field), "sha256:", 32)
    require_hash(grant, "grant_hash", "grant_hash_mismatch")
    approvers = grant.get("approver_principal_ids")
    require_approvers(grant.get("requesting_principal_id"), approvers)
    if len(approvers) < challenge["quorum"]:
        raise VectorError("quorum_not_verified", "grant approver count is below challenge quorum")
    issued_at = require_utc_time(grant.get("issued_at"), "grant issued_at")
    expires_at = require_utc_time(grant.get("expires_at"), "grant expires_at")
    if not issued_at < expires_at or expires_at > require_utc_time(challenge.get("expires_at"), "challenge expires_at"):
        raise VectorError("contract_mismatch", "grant lifetime is invalid")
    require_nonce(grant.get("nonce"), "grant nonce")
    for field in GRANT_BINDING_FIELDS:
        if field not in grant or field not in challenge:
            raise VectorError("grant_binding_rejected", f"grant binding field {field} is missing")
        if grant[field] != challenge[field]:
            raise VectorError("grant_binding_rejected", f"grant {field} does not match challenge")
    if grant["challenge_hash"] != challenge["challenge_hash"]:
        raise VectorError("grant_binding_rejected", "grant challenge hash does not match")


def verify_grant_active(grant, verification_time):
    issued_at = parse_time(grant["issued_at"])
    expires_at = parse_time(grant["expires_at"])
    if verification_time < issued_at or verification_time >= expires_at:
        raise VectorError("inactive_grant", "grant is not active at verification time")


def verify_consumption(consumption, grant):
    require_contract(
        consumption,
        "HELM/GeneratedSpecApprovalConsumption/v1",
        "generated-spec-approval-consumption.v1",
    )
    for field in HASH_FIELDS + ("grant_hash", "challenge_hash", "ceremony_hash", "signer_set_hash"):
        prefixed_bytes(consumption.get(field), "sha256:", 32)
    require_hash(consumption, "consumption_hash", "consumption_hash_mismatch")
    for field in CONSUMPTION_BINDING_FIELDS:
        if field not in consumption or field not in grant:
            raise VectorError("consumption_binding_rejected", f"consumption {field} is missing")
        if consumption[field] != grant[field]:
            raise VectorError("consumption_binding_rejected", f"consumption {field} does not match grant")
    if (
        consumption.get("grant_issued_at") != grant.get("issued_at")
        or consumption.get("grant_expires_at") != grant.get("expires_at")
    ):
        raise VectorError("consumption_binding_rejected", "consumption grant lifetime does not match")
    grant_issued_at = require_utc_time(consumption.get("grant_issued_at"), "consumption grant_issued_at")
    grant_expires_at = require_utc_time(consumption.get("grant_expires_at"), "consumption grant_expires_at")
    consumed_at = require_utc_time(consumption.get("consumed_at"), "consumed_at")
    if consumed_at < grant_issued_at or consumed_at >= grant_expires_at:
        raise VectorError("consumption_binding_rejected", "consumption is outside grant lifetime")
    require_token(consumption.get("consumed_by"), "consumed_by")


def verify_signature(root, descriptor, value, kind, signature):
    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": "ed25519",
        "contract_version": value["contract_version"],
        "domain": f"HELM/GeneratedSpecApproval{kind}Signature/v1",
        f"{kind.lower()}_hash": value[f"{kind.lower()}_hash"],
        "kernel_trust_root_id": value["kernel_trust_root_id"],
        "signing_key_ref": value["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("signature_rejected", f"{kind.lower()} signing payload mismatch")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    raw_signature = prefixed_bytes(signature, "ed25519:", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), raw_signature):
        raise VectorError("signature_rejected", f"{kind.lower()} Ed25519 signature rejected")


def verify_lifecycle(lifecycle, approval_id=None):
    if approval_id is not None and lifecycle.get("approval_id") != approval_id:
        raise VectorError("contract_mismatch", "lifecycle approval_id does not match the ceremony")
    if lifecycle.get("states") != [
        "HOLD_PENDING",
        "CHALLENGE_ISSUED",
        "QUORUM_VERIFIED",
        "GRANT_ISSUED",
        "CONSUMED",
    ]:
        raise VectorError("transition_conflict", "unsupported ceremony state path")
    if lifecycle.get("first_consume_version") != 5 or lifecycle.get("replay_expected_error") != "transition_conflict":
        raise VectorError("transition_conflict", "single-use lifecycle contract drifted")
    if lifecycle.get("recovery_matches_consumption") is not True:
        raise VectorError("transition_conflict", "recovery contract drifted")


def reseal(value, field):
    unsigned = dict(value)
    unsigned.pop(field, None)
    value[field] = sha256_ref(canonical_json(unsigned).encode("utf-8"))


def verify_vector(index, root, mutation=None):
    challenge, _ = load_canonical(root, index["challenge"])
    grant, _ = load_canonical(root, index["grant"])
    consumption, _ = load_canonical(root, index["consumption"])
    lifecycle, _ = load_canonical(root, index["lifecycle"])
    challenge = copy.deepcopy(challenge)
    grant = copy.deepcopy(grant)
    consumption = copy.deepcopy(consumption)
    lifecycle = copy.deepcopy(lifecycle)
    grant_signature = index["grant"]["signature"]
    verification_time = parse_time(index["verification_time"])

    if mutation == "set_challenge_policy_epoch_to_tampered":
        challenge["policy_epoch"] = "epoch-tampered"
    elif mutation == "set_grant_generated_spec_hash_to_tampered":
        grant["generated_spec_hash"] = "sha256:" + "9" * 64
    elif mutation == "set_consumption_grant_id_to_grant_b_and_reseal":
        consumption["grant_id"] = "grant-b"
        reseal(consumption, "consumption_hash")
    elif mutation == "set_verification_time_to_grant_expiry":
        verification_time = parse_time(grant["expires_at"])
    elif mutation == "flip_grant_signature_last_bit":
        grant_signature = flipped_signature(grant_signature)
    elif mutation == "replay_second_consume":
        lifecycle["states"] = lifecycle["states"] + ["CONSUMED"]
    elif mutation == "set_challenge_quorum_above_approvers_and_reseal":
        challenge["quorum"] = len(grant["approver_principal_ids"]) + 1
        reseal(challenge, "challenge_hash")
    elif mutation == "duplicate_grant_approver_and_reseal":
        grant["approver_principal_ids"] = grant["approver_principal_ids"] + grant["approver_principal_ids"][:1]
        reseal(grant, "grant_hash")
    elif mutation == "set_grant_nonce_and_reseal":
        grant["nonce"] = "f" * 64
        reseal(grant, "grant_hash")
    elif mutation == "set_grant_approvers_unsorted_and_reseal":
        grant["approver_principal_ids"] = ["user:approver-z", "user:approver-a"]
        reseal(grant, "grant_hash")
    elif mutation == "set_challenge_issued_at_non_utc_and_reseal":
        challenge["issued_at"] = "2026-07-23T13:01:00+01:00"
        reseal(challenge, "challenge_hash")
    elif mutation == "set_grant_issued_at_non_utc_and_reseal":
        grant["issued_at"] = "2026-07-23T13:01:00+01:00"
        reseal(grant, "grant_hash")
    elif mutation == "set_consumption_consumed_at_non_utc_and_reseal":
        consumption["consumed_at"] = "2026-07-23T13:01:01+01:00"
        reseal(consumption, "consumption_hash")
    elif mutation == "set_challenge_nonce_invalid_and_reseal":
        challenge["nonce"] = "g" * 64
        reseal(challenge, "challenge_hash")
    elif mutation == "set_grant_nonce_invalid_and_reseal":
        grant["nonce"] = "g" * 64
        reseal(grant, "grant_hash")
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    verify_challenge(challenge)
    verify_grant(grant, challenge)
    verify_grant_active(grant, verification_time)
    verify_signature(root, index["grant"], grant, "Grant", grant_signature)
    verify_consumption(consumption, grant)
    verify_signature(root, index["consumption"], consumption, "Consumption", index["consumption"]["signature"])
    verify_lifecycle(lifecycle, challenge["approval_id"])


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if (
        index.get("schema_version") != "generated-spec-approval-ceremony-vectors.v1"
        or index.get("contract_version") != "2026-07-22"
        or index.get("quantum_posture") != "classical_ed25519_only"
        or not index.get("negative_vectors")
    ):
        raise SystemExit("unsupported GeneratedSpec approval ceremony vector contract")

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
        "verified GeneratedSpec approval ceremony vector: "
        f"1 positive, {len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
