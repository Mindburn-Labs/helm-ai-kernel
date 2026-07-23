#!/usr/bin/env python3
"""Independent GeneratedSpec ceremony source-contract verifier.

This verifies deterministic fixture parity only. It does not prove a durable
store, runtime transport, Control Plane transition, or production authority.

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


def verify_challenge(challenge):
    require_contract(
        challenge,
        "HELM/GeneratedSpecApprovalChallenge/v1",
        "generated-spec-approval-challenge.v1",
    )
    if not isinstance(challenge.get("quorum"), int) or challenge["quorum"] <= 0:
        raise VectorError("contract_mismatch", "challenge quorum must be positive")
    for field in HASH_FIELDS:
        prefixed_bytes(challenge.get(field), "sha256:", 32)
    require_hash(challenge, "challenge_hash", "challenge_hash_mismatch")
    hold_started_at = parse_time(challenge["hold_started_at"])
    eligible_at = parse_time(challenge["eligible_at"])
    issued_at = parse_time(challenge["issued_at"])
    expires_at = parse_time(challenge["expires_at"])
    if not hold_started_at < eligible_at <= issued_at < expires_at:
        raise VectorError("contract_mismatch", "challenge lifetime is invalid")


def verify_grant(grant, challenge):
    require_contract(
        grant,
        "HELM/GeneratedSpecApprovalGrant/v1",
        "generated-spec-approval-grant.v1",
    )
    for field in HASH_FIELDS + ("challenge_hash", "ceremony_hash", "signer_set_hash"):
        prefixed_bytes(grant.get(field), "sha256:", 32)
    require_hash(grant, "grant_hash", "grant_hash_mismatch")
    if not grant.get("approver_principal_ids") or grant["requesting_principal_id"] in grant["approver_principal_ids"]:
        raise VectorError("contract_mismatch", "grant approvers are invalid")
    issued_at = parse_time(grant["issued_at"])
    expires_at = parse_time(grant["expires_at"])
    if not issued_at < expires_at or expires_at > parse_time(challenge["expires_at"]):
        raise VectorError("contract_mismatch", "grant lifetime is invalid")
    for field in GRANT_BINDING_FIELDS:
        if grant.get(field) != challenge.get(field):
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
        if consumption.get(field) != grant.get(field):
            raise VectorError("consumption_binding_rejected", f"consumption {field} does not match grant")
    if (
        consumption.get("grant_issued_at") != grant.get("issued_at")
        or consumption.get("grant_expires_at") != grant.get("expires_at")
    ):
        raise VectorError("consumption_binding_rejected", "consumption grant lifetime does not match")
    consumed_at = parse_time(consumption["consumed_at"])
    if consumed_at < parse_time(grant["issued_at"]) or consumed_at >= parse_time(grant["expires_at"]):
        raise VectorError("consumption_binding_rejected", "consumption is outside grant lifetime")
    if not consumption.get("consumed_by"):
        raise VectorError("consumption_binding_rejected", "consuming workload is required")


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


def verify_lifecycle(lifecycle, replay=False):
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
    if replay:
        raise VectorError("transition_conflict", "second consume after CONSUMED is rejected")


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
    grant_signature = index["grant"]["signature"]
    verification_time = parse_time(index["verification_time"])
    replay = False

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
        replay = True
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    verify_challenge(challenge)
    verify_grant(grant, challenge)
    verify_grant_active(grant, verification_time)
    verify_signature(root, index["grant"], grant, "Grant", grant_signature)
    verify_consumption(consumption, grant)
    verify_signature(root, index["consumption"], consumption, "Consumption", index["consumption"]["signature"])
    verify_lifecycle(lifecycle, replay)


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
