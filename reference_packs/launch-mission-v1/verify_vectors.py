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

    envelope = descriptor["envelope"]
    if envelope["approval_artifact_hash"] != claimed_grant_hash or envelope["approval_consumption_hash"] != claimed_consumption_hash:
        raise VectorError("binding_mismatch", "dispatch envelope does not bind canonical approval consumption")


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


def verify_receipt(index, receipt_override=None):
    descriptor = index["receipt"]
    receipt = copy.deepcopy(receipt_override or descriptor["value"])
    claimed_id = receipt["receipt_id"]
    signature = canonical_base64(receipt["signature"], 64)
    receipt["receipt_id"] = ""
    receipt["signature"] = ""
    actual_id = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    if actual_id != claimed_id:
        raise VectorError("receipt_id_mismatch", f"receipt ID {actual_id} != {claimed_id}")
    public_key = prefixed_bytes(descriptor["public_key"], "ed25519:", 32)
    if not verify_ed25519(public_key, claimed_id.encode("ascii"), signature):
        raise VectorError("signature_rejected", "receipt signature rejected")
    if receipt["approval_consumption_hash"] != index["authorization"]["envelope"]["approval_consumption_hash"]:
        raise VectorError("binding_mismatch", "receipt approval lineage differs from dispatch envelope")
    quote_line = index["artifacts"]["route_quote"]["placement_costs"][0]
    if receipt["offer_snapshot_ref"] != quote_line["offer_snapshot_ref"] or receipt["offer_snapshot_hash"] != quote_line["offer_snapshot_hash"]:
        raise VectorError("binding_mismatch", "receipt offer evidence differs from its approved route quote")


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
        "Kernel verdict, receipt, and 4 negative mutations; exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
