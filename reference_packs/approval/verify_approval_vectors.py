#!/usr/bin/env python3
"""Independent approval-vector verifier using only the Python standard library.

quantum_posture: this conformance verifier checks classical Ed25519 signatures;
it does not implement or claim hybrid or post-quantum approval support.
"""

import copy
import hashlib
import json
from datetime import datetime
from pathlib import Path


Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
SQRT_M1 = pow(2, (Q - 1) // 4, Q)
IDENTITY = (0, 1)


class VectorError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_ref(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def prefixed_bytes(value, prefix, size):
    if not isinstance(value, str) or not value.startswith(prefix):
        raise VectorError("invalid_encoding", f"expected {prefix} value")
    try:
        raw = bytes.fromhex(value[len(prefix) :])
    except ValueError as error:
        raise VectorError("invalid_encoding", f"invalid {prefix} hex") from error
    if len(raw) != size or value != prefix + raw.hex():
        raise VectorError("invalid_encoding", f"expected canonical {prefix} value")
    return raw


def recover_x(y, sign):
    x2 = ((y * y - 1) * pow(D * y * y + 1, Q - 2, Q)) % Q
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q:
        x = (x * SQRT_M1) % Q
    if (x * x - x2) % Q:
        raise ValueError("point is not on Ed25519 curve")
    if (x & 1) != sign:
        x = Q - x
    return x


def decode_point(encoded):
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= Q:
        raise ValueError("non-canonical Ed25519 point")
    point = (recover_x(y, sign), y)
    if encode_point(point) != encoded:
        raise ValueError("non-canonical Ed25519 point encoding")
    return point


def encode_point(point):
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def point_add(left, right):
    x1, y1 = left
    x2, y2 = right
    product = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + product, Q - 2, Q) % Q
    y3 = (y1 * y2 + x1 * x2) * pow(1 - product, Q - 2, Q) % Q
    return x3, y3


def scalar_mult(point, scalar):
    result = IDENTITY
    current = point
    while scalar:
        if scalar & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        scalar >>= 1
    return result


BASE_Y = 4 * pow(5, Q - 2, Q) % Q
BASE = (recover_x(BASE_Y, 0), BASE_Y)


def verify_ed25519(public_key, message, signature):
    if len(signature) != 64:
        return False
    try:
        public_point = decode_point(public_key)
        encoded_r = signature[:32]
        r_point = decode_point(encoded_r)
    except ValueError:
        return False
    if public_point == IDENTITY:
        return False
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= L:
        return False
    if scalar_mult(public_point, L) != IDENTITY or scalar_mult(r_point, L) != IDENTITY:
        return False
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % L
    return scalar_mult(BASE, scalar_s) == point_add(r_point, scalar_mult(public_point, challenge))


def load_canonical(root, descriptor):
    filename = descriptor["canonical"]
    text = (root / filename).read_text(encoding="utf-8").removesuffix("\n")
    value = json.loads(text)
    if canonical_json(value) != text:
        raise VectorError("canonical_mismatch", f"{filename}: bytes are not canonical JSON")
    actual_hash = sha256_ref(text.encode("utf-8"))
    if actual_hash != descriptor["sha256"]:
        raise VectorError("hash_mismatch", f"{filename}: {actual_hash} != {descriptor['sha256']}")
    return value, text


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verify_authority_scope(authority_key, challenge, verified_at):
    required = {
        "tenant_id": challenge["tenant_id"],
        "authority workspace": challenge["workspace_id"],
        "authority role": challenge["required_role"],
        "authority action": challenge["action"],
        "authority audience": challenge["audience"],
    }
    if authority_key["tenant_id"] != required["tenant_id"]:
        raise VectorError("authority_rejected", "authority tenant mismatch")
    for field, authority_field in (
        ("authority workspace", "workspace_ids"),
        ("authority role", "roles"),
        ("authority action", "actions"),
        ("authority audience", "audiences"),
    ):
        if required[field] not in authority_key[authority_field]:
            raise VectorError("authority_rejected", f"{field} mismatch")
    if not authority_key["enabled"]:
        raise VectorError("authority_rejected", "authority key disabled")
    if verified_at < parse_time(authority_key["not_before"]) or verified_at >= parse_time(authority_key["not_after"]):
        raise VectorError("authority_rejected", "authority key outside validity window")


def verify_assertion_vector(vector, authority_keys, challenge, challenge_hash, verified_at, root):
    assertion = vector["assertion"]
    key_id = vector["key_id"]
    if assertion["key_id"] != key_id or assertion["signature"] != vector["signature"]:
        raise VectorError("signature_rejected", f"{key_id}: detached assertion envelope mismatch")
    authority_key = authority_keys.get(key_id)
    if authority_key is None:
        raise VectorError("authority_rejected", f"{key_id}: unknown authority key")
    if vector["public_key"] != authority_key["public_key"]:
        raise VectorError("authority_rejected", f"{key_id}: authority public key mismatch")
    verify_authority_scope(authority_key, challenge, verified_at)

    payload_descriptor = {
        "canonical": vector["signing_payload"],
        "sha256": vector["signing_digest"],
    }
    payload, payload_text = load_canonical(root, payload_descriptor)
    expected_payload = {
        field: assertion[field]
        for field in (
            "domain",
            "schema_version",
            "contract_version",
            "challenge_id",
            "challenge_hash",
            "key_id",
            "algorithm",
        )
    }
    if payload != expected_payload:
        raise VectorError("signature_rejected", f"{key_id}: signing payload mismatch")
    if assertion["challenge_id"] != challenge["challenge_id"] or assertion["challenge_hash"] != challenge_hash:
        raise VectorError("challenge_hash_mismatch", f"{key_id}: assertion challenge binding mismatch")

    public_key = prefixed_bytes(vector["public_key"], "ed25519:", 32)
    signature = prefixed_bytes(vector["signature"], "ed25519:", 64)
    digest = hashlib.sha256(payload_text.encode("utf-8")).digest()
    if vector["signing_digest"] != "sha256:" + digest.hex():
        raise VectorError("signature_rejected", f"{key_id}: signing digest mismatch")
    if not verify_ed25519(public_key, digest, signature):
        raise VectorError("signature_rejected", f"{key_id}: Ed25519 signature rejected")
    assertion_hash = sha256_ref(canonical_json(assertion).encode("utf-8"))
    if assertion_hash != vector["assertion_hash"]:
        raise VectorError("signature_rejected", f"{key_id}: assertion hash mismatch")
    return {
        "principal_id": authority_key["principal_id"],
        "credential_id": authority_key["credential_id"],
        "device_id": authority_key["device_id"],
        "key_id": key_id,
        "role": challenge["required_role"],
        "assertion_hash": assertion_hash,
    }


def verify_case(index, case, vectors_by_key, authority_keys, challenge, root):
    key_ids = case["assertion_key_ids"]
    quorum = challenge["quorum"]
    if len(key_ids) < quorum:
        raise VectorError("quorum_not_met", f"{case['id']}: insufficient assertions")
    if len(key_ids) != len(set(key_ids)):
        raise VectorError("duplicate_signer", f"{case['id']}: duplicate key id")
    derived_status = "verified" if len(key_ids) == quorum else "verified_over_quorum"
    if case["expected_status"] != derived_status:
        raise VectorError("status_mismatch", f"{case['id']}: expected_status is not source-derived")

    verified_at = parse_time(index["verified_at"])
    signers = []
    seen_dimensions = {name: set() for name in ("principal_id", "credential_id", "device_id", "key_id", "public_key")}
    for key_id in key_ids:
        vector = vectors_by_key.get(key_id)
        if vector is None:
            raise VectorError("authority_rejected", f"{case['id']}: unknown assertion {key_id}")
        signer = verify_assertion_vector(vector, authority_keys, challenge, index["challenge"]["sha256"], verified_at, root)
        dimensions = dict(signer)
        dimensions["public_key"] = vector["public_key"]
        for name in seen_dimensions:
            value = dimensions[name]
            if value in seen_dimensions[name]:
                raise VectorError("duplicate_signer", f"{case['id']}: duplicate {name}")
            seen_dimensions[name].add(value)
        signers.append(signer)

    signers.sort(key=lambda signer: (signer["principal_id"], signer["credential_id"], signer["device_id"], signer["key_id"]))
    signer_set = {
        "domain": "HELM/ApprovalSignerSet/v1",
        "challenge_hash": index["challenge"]["sha256"],
        "authority_snapshot_hash": index["authority_snapshot"]["sha256"],
        "signers": signers,
    }
    expected_signer_set, _ = load_canonical(root, case["signer_set"])
    if signer_set != expected_signer_set:
        raise VectorError("projection_mismatch", f"{case['id']}: signer-set projection mismatch")

    expected_projection, _ = load_canonical(root, case["verified_projection"])
    projection_fields = (
        "approval_id",
        "tenant_id",
        "workspace_id",
        "audience",
        "pack_id",
        "pack_version",
        "pack_manifest_hash",
        "action",
        "intent_hash",
        "effect_hash",
        "plan_hash",
        "decision",
        "policy_version",
        "policy_epoch",
        "policy_hash",
        "authority_source",
        "authority_version",
        "authority_snapshot_hash",
        "server_identity",
        "required_role",
        "quorum",
    )
    derived_projection = {field: challenge[field] for field in projection_fields}
    derived_projection.update(
        {
            "challenge_id": challenge["challenge_id"],
            "challenge_hash": index["challenge"]["sha256"],
            "signers": signers,
            "signer_set_hash": case["signer_set"]["sha256"],
            "verified_at": index["verified_at"],
        }
    )
    if derived_projection != expected_projection:
        raise VectorError("projection_mismatch", f"{case['id']}: verified projection mismatch")
    return derived_status


def flipped_signature(signature):
    raw = bytearray(prefixed_bytes(signature, "ed25519:", 64))
    raw[-1] ^= 1
    return "ed25519:" + raw.hex()


def run_negative(vector, index, cases_by_id, vectors_by_key, authority_keys, challenge, root):
    mutation = vector["mutation"]
    verified_at = parse_time(index["verified_at"])
    if mutation == "flip_key-a_signature_last_bit":
        mutated = copy.deepcopy(vectors_by_key["key-a"])
        mutated["signature"] = flipped_signature(mutated["signature"])
        mutated["assertion"]["signature"] = mutated["signature"]
        mutated["assertion_hash"] = sha256_ref(canonical_json(mutated["assertion"]).encode("utf-8"))
        verify_assertion_vector(mutated, authority_keys, challenge, index["challenge"]["sha256"], verified_at, root)
        return
    if mutation == "verify_key-a_with_key-b":
        source = vectors_by_key["key-a"]
        payload_text = (root / source["signing_payload"]).read_text(encoding="utf-8").removesuffix("\n")
        digest = hashlib.sha256(payload_text.encode("utf-8")).digest()
        public_key = prefixed_bytes(authority_keys["key-b"]["public_key"], "ed25519:", 32)
        signature = prefixed_bytes(source["signature"], "ed25519:", 64)
        if not verify_ed25519(public_key, digest, signature):
            raise VectorError("signature_rejected", "cross-key signature rejected")
        return
    if mutation == "set_challenge_tenant_id_to_tenant-b":
        mutated = dict(challenge)
        mutated["tenant_id"] = "tenant-b"
        if sha256_ref(canonical_json(mutated).encode("utf-8")) != index["challenge"]["sha256"]:
            raise VectorError("challenge_hash_mismatch", "challenge tenant substitution changed hash")
        return
    if mutation == "set_key-a_assertion_key_id_to_key-b":
        mutated = copy.deepcopy(vectors_by_key["key-a"])
        mutated["assertion"]["key_id"] = "key-b"
        mutated["assertion_hash"] = sha256_ref(canonical_json(mutated["assertion"]).encode("utf-8"))
        verify_assertion_vector(mutated, authority_keys, challenge, index["challenge"]["sha256"], verified_at, root)
        return
    if mutation == "flip_key-c_signature_in_over_quorum":
        mutated_vectors = copy.deepcopy(vectors_by_key)
        mutated = mutated_vectors["key-c"]
        mutated["signature"] = flipped_signature(mutated["signature"])
        mutated["assertion"]["signature"] = mutated["signature"]
        mutated["assertion_hash"] = sha256_ref(canonical_json(mutated["assertion"]).encode("utf-8"))
        verify_case(index, cases_by_id["quorum_2_of_3"], mutated_vectors, authority_keys, challenge, root)
        return
    raise VectorError("unknown_mutation", mutation)


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index["schema_version"] != "approval-vectors.v1" or index["contract_version"] != "2026-07-15":
        raise SystemExit("unsupported approval vector contract")
    if index["quantum_posture"] != "classical_ed25519_only":
        raise SystemExit("unexpected approval vector quantum posture")
    if not index["cases"] or not index["negative_vectors"]:
        raise SystemExit("approval vector cases and negative vectors are required")

    try:
        authority, _ = load_canonical(root, index["authority_snapshot"])
        challenge, _ = load_canonical(root, index["challenge"])
        if challenge["authority_snapshot_hash"] != index["authority_snapshot"]["sha256"]:
            raise VectorError("authority_rejected", "challenge does not bind authority snapshot")
        if challenge["authority_source"] != authority["authority_source"] or challenge["authority_version"] != authority["authority_version"]:
            raise VectorError("authority_rejected", "challenge authority metadata mismatch")

        authority_keys = {}
        for authority_key in authority["keys"]:
            key_id = authority_key["key_id"]
            if key_id in authority_keys:
                raise VectorError("duplicate_signer", f"duplicate authority key {key_id}")
            authority_keys[key_id] = authority_key
        vectors_by_key = {}
        for assertion_vector in index["assertions"]:
            key_id = assertion_vector["key_id"]
            if key_id in vectors_by_key:
                raise VectorError("duplicate_signer", f"duplicate assertion vector {key_id}")
            vectors_by_key[key_id] = assertion_vector
        cases_by_id = {case["id"]: case for case in index["cases"]}
        if len(cases_by_id) != len(index["cases"]):
            raise VectorError("status_mismatch", "duplicate case id")

        statuses = []
        for case in index["cases"]:
            statuses.append(verify_case(index, case, vectors_by_key, authority_keys, challenge, root))

        for negative in index["negative_vectors"]:
            try:
                run_negative(negative, index, cases_by_id, vectors_by_key, authority_keys, challenge, root)
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
        "verified approval vectors: "
        f"{len(index['cases'])} cases ({', '.join(statuses)}), "
        f"{len(index['negative_vectors'])} negative mutations, exact Go/Python parity"
    )


if __name__ == "__main__":
    main()
