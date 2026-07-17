#!/usr/bin/env python3
"""Independent connector release-authority verifier.

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
    load_canonical,
    parse_time,
    prefixed_bytes,
    sha256_ref,
    verify_ed25519,
)


def require_token(authority, field):
    value = authority.get(field)
    if not isinstance(value, str) or not value or len(value) > 512 or any(character.isspace() for character in value):
        raise VectorError("contract_rejected", f"invalid {field}")


def validate_authority(authority):
    if (
        authority.get("schema_version") != "connector-release-authority.v1"
        or authority.get("contract_version") != "2026-07-17"
        or authority.get("algorithm") != "ed25519"
    ):
        raise VectorError("contract_rejected", "unsupported release authority contract")
    revision = authority.get("registry_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise VectorError("contract_rejected", "registry revision must be positive")
    for field in (
        "authority_id",
        "signing_key_ref",
        "connector_id",
        "connector_version",
        "connector_sandbox_profile",
        "connector_drift_policy_ref",
        "connector_signature_ref",
        "connector_signer_id",
        "certification_ref",
        "certification_authority",
    ):
        require_token(authority, field)

    scope = authority.get("scope_kind")
    if scope == "global":
        if "tenant_id" in authority or "workspace_id" in authority:
            raise VectorError("contract_rejected", "global authority carries tenant scope")
    elif scope == "tenant_workspace":
        require_token(authority, "tenant_id")
        require_token(authority, "workspace_id")
    else:
        raise VectorError("contract_rejected", "unsupported scope")
    if authority.get("connector_executor_kind") not in ("digital", "analog"):
        raise VectorError("contract_rejected", "unsupported executor kind")
    if authority.get("state") not in ("certified", "revoked"):
        raise VectorError("contract_rejected", "unsupported state")
    for field in (
        "connector_binary_hash",
        "connector_signature_hash",
        "certification_hash",
    ):
        prefixed_bytes(authority.get(field), "sha256:", 32)

    signed_at = parse_time(authority["signed_at"])
    valid_from = parse_time(authority["valid_from"])
    if signed_at > valid_from:
        raise VectorError("contract_rejected", "signed_at after valid_from")
    if revision == 1:
        if "previous_authority_hash" in authority:
            raise VectorError("contract_rejected", "initial revision has predecessor")
    else:
        prefixed_bytes(authority.get("previous_authority_hash"), "sha256:", 32)

    if authority["state"] == "certified":
        if "valid_until" not in authority or parse_time(authority["valid_until"]) <= valid_from:
            raise VectorError("contract_rejected", "invalid certified validity window")
        if "revokes_authority_hash" in authority:
            raise VectorError("contract_rejected", "certified statement revokes authority")
    else:
        if revision < 2 or "valid_until" in authority:
            raise VectorError("contract_rejected", "invalid revocation revision or expiry")
        prefixed_bytes(authority.get("revokes_authority_hash"), "sha256:", 32)
        if authority["revokes_authority_hash"] != authority["previous_authority_hash"]:
            raise VectorError("contract_rejected", "revocation target is not predecessor")


def reseal(authority):
    unsigned = dict(authority)
    unsigned.pop("authority_hash", None)
    authority["authority_hash"] = sha256_ref(canonical_json(unsigned).encode("utf-8"))


def verify_statement(index, root, descriptor, authority, envelope, signature_value):
    validate_authority(authority)
    claimed_hash = authority.get("authority_hash")
    prefixed_bytes(claimed_hash, "sha256:", 32)
    unsigned = dict(authority)
    unsigned.pop("authority_hash")
    actual_hash = sha256_ref(canonical_json(unsigned).encode("utf-8"))
    if actual_hash != claimed_hash:
        raise VectorError("hash_mismatch", f"authority hash {actual_hash} != {claimed_hash}")
    if envelope.get("authority") != authority:
        raise VectorError("hash_mismatch", "envelope authority mismatch")

    if authority["authority_id"] != index["authority_id"]:
        raise VectorError("authority_rejected", "authority_id mismatch")
    if authority["signing_key_ref"] != "kms://helm/connector-release-authority/key-a":
        raise VectorError("trust_rejected", "signing_key_ref is not pinned")
    signed_at = parse_time(authority["signed_at"])
    if signed_at < parse_time(index["key_not_before"]) or signed_at >= parse_time(index["key_not_after"]):
        raise VectorError("trust_rejected", "statement outside pinned key lifetime")

    payload, payload_text = load_canonical(root, descriptor["signing_payload"])
    expected_payload = {
        "algorithm": authority["algorithm"],
        "authority_hash": claimed_hash,
        "authority_id": authority["authority_id"],
        "contract_version": authority["contract_version"],
        "domain": "HELM/ConnectorReleaseAuthoritySignature/v1",
        "registry_revision": authority["registry_revision"],
        "signing_key_ref": authority["signing_key_ref"],
    }
    if payload != expected_payload:
        raise VectorError("signature_rejected", "signing payload mismatch")
    public_key = prefixed_bytes(index["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(signature_value, "", 64)
    if not verify_ed25519(public_key, payload_text.encode("utf-8"), signature):
        raise VectorError("signature_rejected", "release authority signature rejected")


def verify_vector(index, root, mutation=None):
    certified_descriptor = index["certified"]
    revoked_descriptor = index["revoked"]
    certified, _ = load_canonical(root, certified_descriptor["authority"])
    certified_envelope, _ = load_canonical(root, certified_descriptor["envelope"])
    revoked, _ = load_canonical(root, revoked_descriptor["authority"])
    revoked_envelope, _ = load_canonical(root, revoked_descriptor["envelope"])
    certified = copy.deepcopy(certified)
    certified_envelope = copy.deepcopy(certified_envelope)
    revoked = copy.deepcopy(revoked)
    revoked_envelope = copy.deepcopy(revoked_envelope)
    certified_signature = certified_envelope["signature"]
    hide_revocation = False
    require_certified_current = False
    verification_time = parse_time(index["verification_time"])

    if mutation == "set_certified_connector_version_to_2":
        certified["connector_version"] = "2.0.0"
        certified_envelope["authority"]["connector_version"] = "2.0.0"
    elif mutation == "set_certified_connector_signature_hash_to_tampered":
        value = "sha256:" + "9" * 64
        certified["connector_signature_hash"] = value
        certified_envelope["authority"]["connector_signature_hash"] = value
    elif mutation == "set_certified_authority_id_and_reseal":
        certified["authority_id"] = "spiffe://helm/other-authority"
        reseal(certified)
        certified_envelope["authority"] = copy.deepcopy(certified)
    elif mutation == "set_certified_signing_key_ref_and_reseal":
        certified["signing_key_ref"] = "kms://helm/connector-release-authority/key-b"
        reseal(certified)
        certified_envelope["authority"] = copy.deepcopy(certified)
    elif mutation == "set_certified_registry_revision_to_zero":
        certified["registry_revision"] = 0
        certified_envelope["authority"]["registry_revision"] = 0
    elif mutation == "treat_certified_as_current_after_revocation":
        require_certified_current = True
    elif mutation == "hide_revocation_and_verify_at_certified_expiry":
        hide_revocation = True
        require_certified_current = True
        verification_time = parse_time(certified["valid_until"])
    elif mutation == "flip_certified_envelope_signature_last_bit":
        raw_signature = bytearray.fromhex(certified_signature)
        raw_signature[-1] ^= 1
        certified_signature = raw_signature.hex()
    elif mutation is not None:
        raise VectorError("unknown_mutation", mutation)

    verify_statement(index, root, certified_descriptor, certified, certified_envelope, certified_signature)
    if not hide_revocation:
        verify_statement(index, root, revoked_descriptor, revoked, revoked_envelope, revoked_envelope["signature"])
        if (
            revoked["connector_id"] != certified["connector_id"]
            or revoked["connector_version"] != certified["connector_version"]
            or revoked["scope_kind"] != certified["scope_kind"]
            or revoked["registry_revision"] != certified["registry_revision"] + 1
            or revoked["previous_authority_hash"] != certified["authority_hash"]
            or revoked["revokes_authority_hash"] != certified["authority_hash"]
        ):
            raise VectorError("current_state_rejected", "revocation chain mismatch")

    if require_certified_current:
        if not hide_revocation:
            raise VectorError("current_state_rejected", "later revocation makes certified statement historical")
        if verification_time < parse_time(certified["valid_from"]) or verification_time >= parse_time(certified["valid_until"]):
            raise VectorError("inactive_authority", "certified statement is outside its validity window")


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index["schema_version"] != "connector-release-authority-vectors.v1" or index["contract_version"] != "2026-07-17":
        raise SystemExit("unsupported connector release authority vector contract")
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
        "verified connector release authority vectors: "
        f"2 signed statements (certified -> revoked), {len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
