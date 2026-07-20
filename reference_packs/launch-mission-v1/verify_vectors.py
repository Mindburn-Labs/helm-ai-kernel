#!/usr/bin/env python3
"""Independent verifier for the provider-neutral Launch Mission v1 pack.

The verifier deliberately does not import Go code. It recomputes canonical
artifact hashes, effect idempotency keys, provider certification, the Kernel
verdict, canonical approval grant/consumption, and the append-only receipt
identity using Python only.

quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.
"""

import base64
import copy
import hashlib
import json
import math
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path


APPROVAL_VERIFIER_ROOT = Path(__file__).resolve().parent.parent / "approval"
sys.path.insert(0, str(APPROVAL_VERIFIER_ROOT))

from verify_approval_vectors import (  # noqa: E402
    VectorError,
    canonical_json,
    prefixed_bytes,
    sha256_ref,
    verify_ed25519,
)


MAX_SAFE_INTEGER = 9_007_199_254_740_991
ARTIFACTS = (
    "repository_analysis",
    "workload_graph",
    "provider_capability_profile",
    "offer_snapshot",
    "constraint_set",
    "route_quote",
    "resource_graph",
    "provider_payload_set",
    "route_binding",
)


def canonical_bytes(value):
    assert_safe_integers(value)
    return canonical_json(value).encode("utf-8")


def assert_safe_integers(value, path="$"):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise VectorError("unsafe_integer", f"{path} exceeds the safe-integer range")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer() or abs(value) > MAX_SAFE_INTEGER:
            raise VectorError("unsafe_integer", f"{path} is not an interoperable integer")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            assert_safe_integers(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise VectorError("canonicalization_error", f"{path} has a non-ASCII contract key")
            assert_safe_integers(item, f"{path}.{key}")
        return
    raise VectorError("canonicalization_error", f"{path} has unsupported JSON type {type(value)!r}")


def raw_hex(value, size):
    if not isinstance(value, str):
        raise VectorError("invalid_encoding", "expected lowercase hexadecimal string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise VectorError("invalid_encoding", "invalid hexadecimal string") from error
    if len(raw) != size or value != raw.hex():
        raise VectorError("invalid_encoding", "hexadecimal string is not canonical")
    return raw


def canonical_base64(value, size):
    if not isinstance(value, str):
        raise VectorError("invalid_encoding", "expected base64 string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise VectorError("invalid_encoding", "invalid base64 string") from error
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        raise VectorError("invalid_encoding", "base64 string is not canonical")
    return raw


def verify_artifacts(index):
    artifacts = index["artifacts"]
    expected = index["artifact_hashes"]
    for name in ARTIFACTS:
        actual = sha256_ref(canonical_bytes(artifacts[name]))
        if actual != expected[name]:
            raise VectorError("hash_mismatch", f"{name}: {actual} != {expected[name]}")

    certification = copy.deepcopy(artifacts["provider_certification"])
    claimed_hash = certification["record_hash"]
    signature = prefixed_bytes(certification["signature"], "ed25519:", 64)
    certification["record_hash"] = ""
    certification["signature"] = ""
    payload = canonical_bytes(certification)
    actual_hash = sha256_ref(payload)
    if actual_hash != claimed_hash or claimed_hash != expected["provider_certification"]:
        raise VectorError("hash_mismatch", "provider certification hash mismatch")
    route = artifacts["route_binding"]
    placement = route["placements"][0]
    if placement["provider_certification_hash"] != claimed_hash:
        raise VectorError("binding_mismatch", "route does not bind provider certification")
    public_key = prefixed_bytes(index["certification_public_key"], "ed25519:", 32)
    if not verify_ed25519(public_key, payload, signature):
        raise VectorError("signature_rejected", "provider certification signature rejected")

    # Offer evidence is independently content-addressed and bound to the exact
    # route placement/account through its quote line.
    offer = artifacts["offer_snapshot"]
    line = artifacts["route_quote"]["placement_costs"][0]
    if line["offer_snapshot_ref"] != offer["snapshot_id"] or line["offer_snapshot_hash"] != expected["offer_snapshot"]:
        raise VectorError("binding_mismatch", "route quote does not bind the official offer snapshot")
    if offer["provider_account_hash"] != placement["provider_account_hash"] or offer["status"] != line["credit_status"]:
        raise VectorError("binding_mismatch", "offer snapshot does not bind the placement account or status")


def verify_universal_route(index):
    vector = index["universal_route"]
    artifacts = vector["artifacts"]
    expected = vector["artifact_hashes"]
    for name in (
        "repository_analysis",
        "workload_graph",
        "constraint_set",
        "route_quote",
        "resource_graph",
        "provider_payload_set",
        "route_binding",
    ):
        actual = sha256_ref(canonical_bytes(artifacts[name]))
        if actual != expected[name]:
            raise VectorError("hash_mismatch", f"universal route {name}: {actual} != {expected[name]}")

    profiles = artifacts["provider_capability_profiles"]
    for profile_id, profile in profiles.items():
        actual = sha256_ref(canonical_bytes(profile))
        if actual != expected["provider_capability_profiles"].get(profile_id):
            raise VectorError("hash_mismatch", f"universal provider profile {profile_id} mismatch")
    offers = artifacts["offer_snapshots"]
    for snapshot_id, offer in offers.items():
        actual = sha256_ref(canonical_bytes(offer))
        if actual != expected["offer_snapshots"].get(snapshot_id):
            raise VectorError("hash_mismatch", f"universal offer snapshot {snapshot_id} mismatch")

    route = artifacts["route_binding"]
    graph = artifacts["workload_graph"]
    quote = artifacts["route_quote"]
    placements = route["placements"]
    provider_ids = {placement["provider_id"] for placement in placements}
    if len(placements) < 2 or len(provider_ids) < 2:
        raise VectorError("contract_mismatch", "universal route must exercise multiple cloud placements")
    if not any(node["lifecycle_class"] == "STATEFUL_DATA" for node in graph["nodes"]):
        raise VectorError("contract_mismatch", "universal route must exercise a stateful workload")
    assigned = sorted(node_id for placement in placements for node_id in placement["workload_node_ids"])
    workload_nodes = sorted(node["node_id"] for node in graph["nodes"])
    if assigned != workload_nodes:
        raise VectorError("binding_mismatch", "universal route does not assign every workload node exactly once")
    if not route["placement_dependencies"]:
        raise VectorError("binding_mismatch", "universal route omits its cross-cloud dependency")

    lines = {line["placement_id"]: line for line in quote["placement_costs"]}
    if set(lines) != {placement["placement_id"] for placement in placements}:
        raise VectorError("binding_mismatch", "universal quote placements differ from its route")
    for placement in placements:
        profile = profiles.get(placement["provider_profile_ref"])
        line = lines[placement["placement_id"]]
        offer = offers.get(line["offer_snapshot_ref"])
        if profile is None or offer is None:
            raise VectorError("binding_mismatch", "universal route references missing provider evidence")
        if line["price_evidence_hash"] != profile["pricing_evidence_hash"] or line["terms_evidence_hash"] != profile["terms_evidence_hash"]:
            raise VectorError("binding_mismatch", "universal quote differs from its provider price or terms evidence")
        if offer["provider_id"] != placement["provider_id"] or offer["provider_account_hash"] != placement["provider_account_hash"]:
            raise VectorError("binding_mismatch", "universal offer differs from its provider account")


def verify_effect_inputs(index):
    seen = set()
    for vector in index["effect_inputs"]:
        effect_id = vector["effect_id"]
        input_value = vector["input"]
        if effect_id in seen or input_value.get("effect_id") != effect_id:
            raise VectorError("binding_mismatch", f"duplicate or mismatched effect {effect_id}")
        if input_value.get("schema_version") != "launch_effect_input.v1":
            raise VectorError("contract_mismatch", f"{effect_id} input contract mismatch")
        seen.add(effect_id)
        actual = sha256_ref(canonical_bytes(input_value))
        if actual != vector["idempotency_key"]:
            raise VectorError("hash_mismatch", f"{effect_id} idempotency key mismatch")
    if len(seen) != 6:
        raise VectorError("contract_mismatch", "reference pack must cover all six preview effects")


def verify_approval_authority(index):
    descriptor = index["authorization"]
    authority = descriptor["approval_authority"]
    public_key = prefixed_bytes(descriptor["approval_public_key"], "ed25519:", 32)

    grant = copy.deepcopy(authority["grant"])
    claimed_grant_hash = grant.pop("grant_hash")
    actual_grant_hash = sha256_ref(canonical_bytes(grant))
    if actual_grant_hash != claimed_grant_hash:
        raise VectorError("hash_mismatch", "canonical approval grant hash mismatch")
    grant_payload = {
        "algorithm": authority["grant_signature_algorithm"],
        "contract_version": grant["contract_version"],
        "domain": "HELM/ApprovalGrantSignature/v1",
        "grant_hash": claimed_grant_hash,
        "kernel_trust_root_id": grant["kernel_trust_root_id"],
        "signing_key_ref": grant["signing_key_ref"],
    }
    grant_signature = raw_hex(authority["grant_signature"], 64)
    if not verify_ed25519(public_key, canonical_bytes(grant_payload), grant_signature):
        raise VectorError("signature_rejected", "canonical approval grant signature rejected")

    consumption = copy.deepcopy(authority["consumption"])
    claimed_consumption_hash = consumption.pop("consumption_hash")
    actual_consumption_hash = sha256_ref(canonical_bytes(consumption))
    if actual_consumption_hash != claimed_consumption_hash:
        raise VectorError("hash_mismatch", "canonical approval consumption hash mismatch")
    consumption_payload = {
        "algorithm": authority["consumption_signature_algorithm"],
        "consumption_hash": claimed_consumption_hash,
        "contract_version": consumption["contract_version"],
        "domain": "HELM/ApprovalGrantConsumptionSignature/v1",
        "kernel_trust_root_id": consumption["kernel_trust_root_id"],
        "signing_key_ref": consumption["signing_key_ref"],
    }
    consumption_signature = raw_hex(authority["consumption_signature"], 64)
    if not verify_ed25519(public_key, canonical_bytes(consumption_payload), consumption_signature):
        raise VectorError("signature_rejected", "canonical approval consumption signature rejected")

    connector_authority = copy.deepcopy(grant["connector_authority"])
    claimed_connector_authority_hash = connector_authority.pop("authority_hash")
    actual_connector_authority_hash = sha256_ref(canonical_bytes(connector_authority))
    if actual_connector_authority_hash != claimed_connector_authority_hash:
        raise VectorError("hash_mismatch", "canonical connector authority hash mismatch")
    envelope = descriptor["envelope"]
    expected_connector_action = envelope["input"].get("provider_action_urn", envelope["action_urn"])
    if connector_authority.get("connector_action") != expected_connector_action:
        raise VectorError("binding_mismatch", "connector authority does not bind the dispatched connector action")
    for field in (
        "release_scope_kind",
        "release_authority_id",
        "release_authority_hash",
        "connector_signature_hash",
    ):
        if not connector_authority.get(field):
            raise VectorError("contract_mismatch", f"connector authority is missing {field}")
    revision = connector_authority.get("release_registry_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1 or revision > MAX_SAFE_INTEGER:
        raise VectorError("contract_mismatch", "connector release registry revision is not a positive JCS-safe integer")
    if authority["consumption"]["connector_authority"] != grant["connector_authority"]:
        raise VectorError("binding_mismatch", "approval consumption changed connector authority")

    dispatch = copy.deepcopy(authority["dispatch_admission"])
    claimed_dispatch_hash = dispatch.pop("admission_hash")
    actual_dispatch_hash = sha256_ref(canonical_bytes(dispatch))
    if actual_dispatch_hash != claimed_dispatch_hash:
        raise VectorError("hash_mismatch", "canonical dispatch admission hash mismatch")
    dispatch_payload = {
        "algorithm": authority["dispatch_signature_algorithm"],
        "contract_version": dispatch["contract_version"],
        "domain": "HELM/ApprovalDispatchAdmissionSignature/v1",
        "admission_hash": claimed_dispatch_hash,
        "kernel_trust_root_id": dispatch["kernel_trust_root_id"],
        "signing_key_ref": dispatch["signing_key_ref"],
    }
    dispatch_signature = raw_hex(authority["dispatch_signature"], 64)
    if not verify_ed25519(public_key, canonical_bytes(dispatch_payload), dispatch_signature):
        raise VectorError("signature_rejected", "canonical dispatch admission signature rejected")
    if (
        dispatch["consumption_hash"] != claimed_consumption_hash
        or dispatch["connector_authority"] != grant["connector_authority"]
    ):
        raise VectorError(
            "binding_mismatch",
            "dispatch admission changed approval consumption or connector authority",
        )

    if envelope["approval_artifact_hash"] != claimed_grant_hash or envelope["approval_consumption_hash"] != claimed_consumption_hash:
        raise VectorError("binding_mismatch", "dispatch envelope does not bind canonical approval consumption")
    if envelope["dispatch_admission_hash"] != claimed_dispatch_hash:
        raise VectorError("binding_mismatch", "dispatch envelope does not bind canonical dispatch admission")
    if (
        envelope["connector_authority_ref"] != grant["connector_authority"]["binding_ref"]
        or envelope["connector_authority_hash"] != claimed_connector_authority_hash
    ):
        raise VectorError("binding_mismatch", "dispatch envelope does not bind canonical connector authority")


def verify_authorization(index, signature_override=None):
    descriptor = index["authorization"]
    envelope = copy.deepcopy(descriptor["envelope"])
    claimed_hash = envelope["kernel_verdict_hash"]
    signature_value = signature_override or envelope["kernel_verdict_signature"]
    envelope["kernel_verdict_hash"] = ""
    envelope["kernel_verdict_signature"] = ""
    payload = canonical_bytes(envelope)
    actual_hash = sha256_ref(payload)
    if actual_hash != claimed_hash:
        raise VectorError("hash_mismatch", "Kernel verdict hash mismatch")
    public_key = prefixed_bytes(descriptor["verdict_public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "ed25519:", 64)
    if not verify_ed25519(public_key, payload, signature):
        raise VectorError("signature_rejected", "Kernel verdict signature rejected")
    if envelope["input_hash"] != envelope["idempotency_key"]:
        raise VectorError("binding_mismatch", "dispatch input and idempotency hashes differ")


RECEIPT_CHAIN_FIELDS = (
    "effect_id",
    "tenant_id",
    "workspace_id",
    "mission_id",
    "effect_ordinal",
    "input_schema_hash",
    "input_hash",
    "idempotency_key",
    "plan_hash",
    "request_hash",
    "args_c14n_hash",
    "kernel_verdict_ref",
    "kernel_verdict_hash",
    "principal",
    "audience",
    "kernel_trust_root_id",
    "approval_artifact_ref",
    "approval_artifact_hash",
    "approval_consumption_ref",
    "approval_consumption_hash",
    "dispatch_admission_ref",
    "dispatch_admission_hash",
    "effect_reservation_ref",
    "effect_reservation_hash",
    "effect_permit_ref",
    "effect_permit_hash",
    "permit_nonce",
    "permit_consumption_ref",
    "permit_consumption_hash",
    "proof_session_ref",
    "evidence_reservation_ref",
    "policy_epoch",
    "emergency_fence_epoch",
    "connector_contract_hash",
    "connector_authority_ref",
    "connector_authority_hash",
    "dependency_set_ref",
    "dependency_set_hash",
    "route_binding_ref",
    "route_binding_hash",
    "route_placement_id",
    "provider_id",
    "provider_account_ref",
    "provider_account_hash",
    "region_id",
    "offering_id",
    "provider_connector_id",
    "provider_connector_contract_hash",
    "provider_action_urn",
    "provider_payload_hash",
    "provider_capability_profile_ref",
    "provider_capability_profile_hash",
    "provider_certification_ref",
    "provider_certification_hash",
    "offer_snapshot_ref",
    "offer_snapshot_hash",
    "price_evidence_hash",
    "terms_evidence_hash",
)


RECEIPT_AUTHORITY_FIELDS = RECEIPT_CHAIN_FIELDS


def canonical_ref_list(refs, field):
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        raise VectorError("invalid_encoding", f"{field} must be an array of strings")
    if refs != sorted(refs) or len(refs) != len(set(refs)) or any(not ref for ref in refs):
        raise VectorError("invalid_encoding", f"{field} must be strictly sorted and unique")


def verify_receipt_evidence(receipt, dag):
    nodes = dag.get("nodes", [])
    if not nodes:
        raise VectorError("binding_mismatch", "receipt evidence DAG is empty")
    by_hash = {}
    for node in nodes:
        node_hash = node.get("node_hash", "")
        raw_hex(node_hash.removeprefix("sha256:"), 32)
        if not node_hash.startswith("sha256:") or node_hash in by_hash:
            raise VectorError("invalid_encoding", "receipt evidence node hash is noncanonical or duplicated")
        if node.get("proof_session_ref") != receipt["proof_session_ref"] or node.get("evidence_reservation_ref") != receipt["evidence_reservation_ref"]:
            raise VectorError("binding_mismatch", "receipt evidence escaped its source-owned reservation")
        lamport = node.get("lamport")
        if not isinstance(lamport, int) or isinstance(lamport, bool) or lamport < 1 or lamport >= receipt["lamport"]:
            raise VectorError("binding_mismatch", "receipt evidence does not precede its receipt")
        parents = node.get("parent_hashes", [])
        artifacts = node.get("artifact_refs", [])
        canonical_ref_list(parents, "evidence parent hashes")
        canonical_ref_list(artifacts, "evidence artifact refs")
        for parent_hash in parents:
            if not parent_hash.startswith("sha256:"):
                raise VectorError("invalid_encoding", "evidence parent hash is not canonical")
            raw_hex(parent_hash.removeprefix("sha256:"), 32)
        forbidden = {
            receipt.get("receipt_id", ""),
            receipt.get("previous_receipt_id", ""),
            receipt.get("receipt_chain_id", ""),
            receipt.get("evidence_pack_ref", ""),
            receipt.get("evidence_pack_hash", ""),
            "sha256:" + receipt.get("receipt_id", ""),
            "sha256:" + receipt.get("previous_receipt_id", ""),
        }
        for artifact in artifacts:
            lowered = artifact.lower()
            if artifact in forbidden or lowered.startswith("receipt:") or lowered.startswith("evidencepack:"):
                raise VectorError("evidence_cycle", "receipt evidence depends on a receipt or EvidencePack")
        by_hash[node_hash] = node

    top = receipt["proofgraph_node"]
    if top not in by_hash:
        raise VectorError("binding_mismatch", "receipt ProofGraph node is absent from its evidence DAG")
    state = {}

    def visit(node_hash):
        if state.get(node_hash) == 1:
            raise VectorError("evidence_cycle", "receipt evidence DAG contains a cycle")
        if state.get(node_hash) == 2:
            return
        node = by_hash.get(node_hash)
        if node is None:
            raise VectorError("binding_mismatch", "receipt evidence DAG omits a parent")
        state[node_hash] = 1
        for parent_hash in node.get("parent_hashes", []):
            parent = by_hash.get(parent_hash)
            if parent is None:
                raise VectorError("binding_mismatch", "receipt evidence DAG omits a parent")
            visit(parent_hash)
            if parent["lamport"] >= node["lamport"]:
                raise VectorError("binding_mismatch", "evidence parent does not precede its child")
        state[node_hash] = 2

    visit(top)


def verify_receipt(index, receipt_override=None, authority_override=None, evidence_override=None):
    descriptor = index["receipt"]
    sealed_receipt = copy.deepcopy(receipt_override or descriptor["value"])
    claimed_id = sealed_receipt["receipt_id"]
    signature = canonical_base64(sealed_receipt["signature"], 64)
    signing_projection = copy.deepcopy(sealed_receipt)
    signing_projection["receipt_id"] = ""
    signing_projection["signature"] = ""
    actual_id = hashlib.sha256(canonical_bytes(signing_projection)).hexdigest()
    if actual_id != claimed_id:
        raise VectorError("receipt_id_mismatch", f"receipt ID {actual_id} != {claimed_id}")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    if not verify_ed25519(public_key, claimed_id.encode("ascii"), signature):
        raise VectorError("signature_rejected", "receipt signature rejected")
    receipt = sealed_receipt
    chain_projection = {field: receipt[field] for field in RECEIPT_CHAIN_FIELDS if field in receipt}
    expected_chain_id = sha256_ref(canonical_bytes(chain_projection))
    if receipt.get("receipt_chain_id") != expected_chain_id:
        raise VectorError("hash_mismatch", "receipt immutable dispatch chain ID mismatch")
    if receipt["payload_hash"] != receipt["request_hash"] or receipt["decision_id"] != receipt["kernel_verdict_ref"]:
        raise VectorError("binding_mismatch", "receipt payload or decision differs from dispatched authority")

    authority = copy.deepcopy(authority_override or descriptor["authority_binding"])
    field_map = {field: field for field in RECEIPT_AUTHORITY_FIELDS}
    field_map["tool"] = "connector_id"
    field_map["action"] = "action_urn"
    for receipt_field, authority_field in field_map.items():
        if receipt.get(receipt_field, "") != authority.get(authority_field, ""):
            raise VectorError("binding_mismatch", f"receipt authority field {receipt_field} mismatch")

    reservation_hash = receipt.get("effect_reservation_hash", "")
    if not reservation_hash.startswith("sha256:"):
        raise VectorError("invalid_encoding", "receipt durable effect reservation hash is missing")
    raw_hex(reservation_hash.removeprefix("sha256:"), 32)
    quote_line = index["artifacts"]["route_quote"]["placement_costs"][0]
    if receipt["offer_snapshot_ref"] != quote_line["offer_snapshot_ref"] or receipt["offer_snapshot_hash"] != quote_line["offer_snapshot_hash"]:
        raise VectorError("binding_mismatch", "receipt offer evidence differs from its approved route quote")
    verify_receipt_evidence(receipt, copy.deepcopy(evidence_override or descriptor["evidence_dag"]))


def verify_integer_equivalence(index):
    parsed = []
    for spelling in index["integer_equivalence"]:
        try:
            number = Decimal(spelling)
        except InvalidOperation as error:
            raise VectorError("canonicalization_error", f"invalid integer spelling {spelling}") from error
        if number != number.to_integral_value() or abs(number) > MAX_SAFE_INTEGER:
            raise VectorError("unsafe_integer", f"non-interoperable integer spelling {spelling}")
        parsed.append(int(number))
    if not parsed or len(set(parsed)) != 1:
        raise VectorError("canonicalization_error", "equivalent integer spellings did not normalize")


def flipped_ed25519(value):
    raw = bytearray(prefixed_bytes(value, "ed25519:", 64))
    raw[-1] ^= 1
    return "ed25519:" + bytes(raw).hex()


def verify_negative_vectors(index):
    expected = {item["id"]: item["expected_error"] for item in index["negative_vectors"]}
    observed = {}

    route = copy.deepcopy(index["artifacts"]["route_binding"])
    route["mission_id"] = "mission-tampered"
    if sha256_ref(canonical_bytes(route)) != index["artifact_hashes"]["route_binding"]:
        observed["route_hash_tamper"] = "hash_mismatch"

    try:
        verify_authorization(index, flipped_ed25519(index["authorization"]["envelope"]["kernel_verdict_signature"]))
    except VectorError as error:
        observed["verdict_signature_tamper"] = error.code

    receipt = copy.deepcopy(index["receipt"]["value"])
    receipt["result_hash"] = "sha256:" + "f" * 64
    try:
        verify_receipt(index, receipt)
    except VectorError as error:
        observed["receipt_result_tamper"] = error.code

    authority = copy.deepcopy(index["receipt"]["authority_binding"])
    authority["provider_account_ref"] = "account:other"
    try:
        verify_receipt(index, authority_override=authority)
    except VectorError as error:
        observed["receipt_authority_tamper"] = error.code

    evidence = copy.deepcopy(index["receipt"]["evidence_dag"])
    top = evidence["nodes"][0]
    other_hash = "sha256:" + "1" * 64
    top["parent_hashes"] = [other_hash]
    evidence["nodes"].append(
        {
            "node_hash": other_hash,
            "parent_hashes": [top["node_hash"]],
            "artifact_refs": [],
            "proof_session_ref": top["proof_session_ref"],
            "evidence_reservation_ref": top["evidence_reservation_ref"],
            "lamport": top["lamport"],
        }
    )
    try:
        verify_receipt(index, evidence_override=evidence)
    except VectorError as error:
        observed["receipt_evidence_cycle"] = error.code

    try:
        assert_safe_integers(MAX_SAFE_INTEGER + 1)
    except VectorError as error:
        observed["unsafe_integer"] = error.code

    if observed != expected:
        raise VectorError("negative_mismatch", f"observed {observed}, expected {expected}")


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index.get("schema_version") != "launch-mission-reference-v1" or index.get("contract_version") != "1.1.0-alpha.1":
        raise SystemExit("unsupported Launch Mission reference-pack contract")
    if index.get("canonicalization") != "RFC8785_JCS_SAFE_INTEGER_INPUTS" or index.get("quantum_posture") != "classical_ed25519_only":
        raise SystemExit("unexpected canonicalization or signature posture")

    try:
        verify_integer_equivalence(index)
        verify_artifacts(index)
        verify_universal_route(index)
        verify_effect_inputs(index)
        verify_approval_authority(index)
        verify_authorization(index)
        verify_receipt(index)
        verify_negative_vectors(index)
    except VectorError as error:
        raise SystemExit(f"{error.code}: {error}") from error

    print(
        "verified Launch Mission v1 reference pack: "
        "10 authority artifact hashes, a multi-provider/stateful universal route, 6 effect inputs, provider certification, canonical approval, "
        "Kernel verdict, receipt, and 6 negative mutations; exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
