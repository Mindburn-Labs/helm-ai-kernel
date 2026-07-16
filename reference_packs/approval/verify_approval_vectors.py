#!/usr/bin/env python3
"""Independent approval-vector verifier using only the Python standard library.

quantum_posture: this conformance verifier checks classical Ed25519 signatures;
it does not implement or claim hybrid or post-quantum approval support.
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path


Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, Q - 2, Q)) % Q
SQRT_M1 = pow(2, (Q - 1) // 4, Q)
IDENTITY = (0, 1)
PORTABLE_SIGNER_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:/@+-")


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_ref(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def portable_signer_identifier(value):
    return isinstance(value, str) and bool(value) and all(char in PORTABLE_SIGNER_CHARS for char in value)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def prefixed_bytes(value, prefix, size):
    if not isinstance(value, str) or not value.startswith(prefix):
        raise ValueError(f"expected {prefix} value")
    raw = bytes.fromhex(value[len(prefix) :])
    if len(raw) != size or value != prefix + raw.hex():
        raise ValueError(f"expected canonical {prefix} value")
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
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = decode_point(public_key)
        encoded_r = signature[:32]
        r_point = decode_point(encoded_r)
    except ValueError:
        return False
    if public_point == IDENTITY or r_point == IDENTITY:
        return False
    scalar_s = int.from_bytes(signature[32:], "little")
    if scalar_s >= L:
        return False
    if scalar_mult(public_point, L) != IDENTITY or scalar_mult(r_point, L) != IDENTITY:
        return False
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public_key + message).digest(), "little") % L
    return scalar_mult(BASE, scalar_s) == point_add(r_point, scalar_mult(public_point, challenge))


def load_canonical(root, filename, expected_hash):
    text = (root / filename).read_text(encoding="utf-8").removesuffix("\n")
    value = json.loads(text)
    if canonical_json(value) != text:
        raise SystemExit(f"{filename}: bytes are not canonical JSON")
    actual_hash = sha256_ref(text.encode("utf-8"))
    if actual_hash != expected_hash:
        raise SystemExit(f"{filename}: hash mismatch {actual_hash} != {expected_hash}")
    return value, text


def main():
    root = Path(__file__).resolve().parent
    index = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    if index["schema_version"] != "approval-vectors.v1" or index["contract_version"] != "2026-07-15":
        raise SystemExit("unsupported approval vector contract")
    if index["quantum_posture"] != "classical_ed25519_only":
        raise SystemExit("unexpected approval vector quantum posture")

    authority, _ = load_canonical(root, index["authority_snapshot"]["canonical"], index["authority_snapshot"]["sha256"])
    challenge, challenge_text = load_canonical(root, index["challenge"]["canonical"], index["challenge"]["sha256"])
    if challenge["authority_snapshot_hash"] != index["authority_snapshot"]["sha256"]:
        raise SystemExit("challenge does not bind authority snapshot")
    if challenge["authority_source"] != authority["authority_source"] or challenge["authority_version"] != authority["authority_version"]:
        raise SystemExit("challenge authority metadata mismatch")
    if sha256_ref(challenge_text.encode("utf-8")) != index["challenge"]["sha256"]:
        raise SystemExit("challenge hash mismatch")

    verified_at = parse_time(index["verified_at"])
    if not (parse_time(challenge["issued_at"]) <= verified_at < parse_time(challenge["expires_at"])):
        raise SystemExit("verified_at is outside the issued challenge window")

    authority_keys = {key["key_id"]: key for key in authority["keys"]}
    if len(authority_keys) != len(authority["keys"]):
        raise SystemExit("authority snapshot repeats a key_id")
    for key in authority["keys"]:
        for field in ("key_id", "principal_id", "credential_id", "device_id"):
            if not portable_signer_identifier(key[field]):
                raise SystemExit(f"{key['key_id']}: authority {field} is not a portable ASCII signer identifier")
        if key["tenant_id"] != challenge["tenant_id"]:
            raise SystemExit(f"{key['key_id']}: authority tenant mismatch")
        for field, required in (
            ("workspace_ids", challenge["workspace_id"]),
            ("roles", challenge["required_role"]),
            ("actions", challenge["action"]),
            ("audiences", challenge["audience"]),
        ):
            if required not in key[field]:
                raise SystemExit(f"{key['key_id']}: authority {field} mismatch")
        if not key["enabled"] or not (parse_time(key["not_before"]) <= verified_at < parse_time(key["not_after"])):
            raise SystemExit(f"{key['key_id']}: authority key is inactive")

    verified_by_key = {}
    verification_material = {}
    for vector in index["assertions"]:
        payload, payload_text = load_canonical(root, vector["signing_payload"], vector["signing_digest"])
        assertion = vector["assertion"]
        key_id = vector["key_id"]
        if key_id != assertion["key_id"] or vector["signature"] != assertion["signature"]:
            raise SystemExit(f"{key_id}: assertion envelope mismatch")
        if not portable_signer_identifier(key_id):
            raise SystemExit(f"{key_id}: assertion key_id is not a portable ASCII signer identifier")
        authority_key = authority_keys[key_id]
        if payload != {field: assertion[field] for field in ("domain", "schema_version", "contract_version", "challenge_id", "challenge_hash", "key_id", "algorithm")}:
            raise SystemExit(f"{key_id}: assertion signing payload mismatch")
        if assertion["challenge_id"] != challenge["challenge_id"] or assertion["challenge_hash"] != index["challenge"]["sha256"]:
            raise SystemExit(f"{key_id}: assertion challenge binding mismatch")
        if vector["public_key"] != authority_key["public_key"]:
            raise SystemExit(f"{key_id}: authority public key mismatch")
        public_key = prefixed_bytes(vector["public_key"], "ed25519:", 32)
        signature = prefixed_bytes(vector["signature"], "ed25519:", 64)
        digest = hashlib.sha256(payload_text.encode("utf-8")).digest()
        if not verify_ed25519(public_key, digest, signature):
            raise SystemExit(f"{key_id}: Ed25519 signature rejected")
        assertion_hash = sha256_ref(canonical_json(assertion).encode("utf-8"))
        if assertion_hash != vector["assertion_hash"]:
            raise SystemExit(f"{key_id}: assertion hash mismatch")
        verified_by_key[key_id] = {
            "principal_id": authority_key["principal_id"],
            "credential_id": authority_key["credential_id"],
            "device_id": authority_key["device_id"],
            "key_id": key_id,
            "role": challenge["required_role"],
            "assertion_hash": assertion_hash,
        }
        verification_material[key_id] = (assertion, digest, public_key, signature)

    challenge_fields = (
        "approval_id", "tenant_id", "workspace_id", "audience", "pack_id", "pack_version",
        "pack_manifest_hash", "action", "intent_hash", "effect_hash", "plan_hash", "decision",
        "policy_version", "policy_epoch", "policy_hash", "authority_source", "authority_version",
        "authority_snapshot_hash", "server_identity", "required_role", "quorum",
    )
    case_ids = set()
    for case in index["cases"]:
        case_id = case["id"]
        if case_id in case_ids:
            raise SystemExit(f"duplicate positive case {case_id}")
        case_ids.add(case_id)
        key_ids = case["assertion_key_ids"]
        if len(key_ids) != len(set(key_ids)):
            raise SystemExit(f"{case_id}: repeated assertion key")
        try:
            verified_signers = [verified_by_key[key_id] for key_id in key_ids]
        except KeyError as exc:
            raise SystemExit(f"{case_id}: unknown assertion key {exc.args[0]}") from exc
        verified_signers.sort(key=lambda signer: (
            signer["principal_id"], signer["credential_id"], signer["device_id"], signer["key_id"]
        ))
        for field in ("principal_id", "credential_id", "device_id", "key_id"):
            if len({signer[field] for signer in verified_signers}) != len(verified_signers):
                raise SystemExit(f"{case_id}: repeated signer {field}")
        if len({authority_keys[key_id]["public_key"] for key_id in key_ids}) != len(key_ids):
            raise SystemExit(f"{case_id}: repeated signer public key")
        signer_set, _ = load_canonical(
            root, case["signer_set"]["canonical"], case["signer_set"]["sha256"]
        )
        projection, _ = load_canonical(
            root, case["verified_projection"]["canonical"], case["verified_projection"]["sha256"]
        )
        expected_signer_set = {
            "domain": "HELM/ApprovalSignerSet/v1",
            "challenge_hash": index["challenge"]["sha256"],
            "authority_snapshot_hash": index["authority_snapshot"]["sha256"],
            "signers": verified_signers,
        }
        if signer_set != expected_signer_set:
            raise SystemExit(f"{case_id}: sorted signer-set projection mismatch")
        if projection["signers"] != verified_signers or projection["signer_set_hash"] != case["signer_set"]["sha256"]:
            raise SystemExit(f"{case_id}: verified projection signer evidence mismatch")
        if projection["verified_at"] != index["verified_at"]:
            raise SystemExit(f"{case_id}: verified projection time mismatch")
        for field in challenge_fields:
            if projection[field] != challenge[field]:
                raise SystemExit(f"{case_id}: verified projection lost challenge field {field}")
        expected_status = "verified" if len(key_ids) == challenge["quorum"] else "verified_over_quorum"
        if case["expected_status"] != expected_status:
            raise SystemExit(f"{case_id}: incorrect expected status")

    if case_ids != {"quorum_2_of_2", "quorum_2_of_3"}:
        raise SystemExit("approval pack must pin both 2-of-2 and 2-of-3 cases")

    negative_results = {}
    assertion_a, digest_a, public_a, signature_a = verification_material["key-a"]
    tampered_signature = bytearray(signature_a)
    tampered_signature[-1] ^= 1
    negative_results["flip_signature_last_bit"] = (
        "unexpected_accept" if verify_ed25519(public_a, digest_a, bytes(tampered_signature)) else "signature_rejected"
    )
    public_b = prefixed_bytes(authority_keys["key-b"]["public_key"], "ed25519:", 32)
    negative_results["verify_key_a_with_key_b"] = (
        "unexpected_accept" if verify_ed25519(public_b, digest_a, signature_a) else "signature_rejected"
    )
    tampered_challenge = dict(challenge)
    tampered_challenge["tenant_id"] = "tenant-b"
    negative_results["set_challenge_tenant_id_to_tenant-b"] = (
        "unexpected_accept"
        if sha256_ref(canonical_json(tampered_challenge).encode("utf-8")) == index["challenge"]["sha256"]
        else "challenge_hash_mismatch"
    )
    substituted_assertion = dict(assertion_a)
    substituted_assertion["key_id"] = "key-b"
    substituted_payload = {field: substituted_assertion[field] for field in (
        "domain", "schema_version", "contract_version", "challenge_id", "challenge_hash", "key_id", "algorithm"
    )}
    substituted_digest = hashlib.sha256(canonical_json(substituted_payload).encode("utf-8")).digest()
    negative_results["set_key-a_assertion_key_id_to_key-b"] = (
        "unexpected_accept" if verify_ed25519(public_b, substituted_digest, signature_a) else "signature_rejected"
    )
    negative_results["set_authority_principal_id_to_principal-😀"] = (
        "unexpected_accept" if portable_signer_identifier("principal-😀") else "identifier_rejected"
    )
    _, digest_c, public_c, signature_c = verification_material["key-c"]
    tampered_surplus_signature = bytearray(signature_c)
    tampered_surplus_signature[-1] ^= 1
    negative_results["flip_key-c_signature_in_over_quorum"] = (
        "unexpected_accept"
        if verify_ed25519(public_c, digest_c, bytes(tampered_surplus_signature))
        else "signature_rejected"
    )

    seen_negative_ids = set()
    seen_mutations = set()
    for vector in index["negative_vectors"]:
        if vector["id"] in seen_negative_ids:
            raise SystemExit(f"duplicate negative vector {vector['id']}")
        seen_negative_ids.add(vector["id"])
        if vector["mutation"] in seen_mutations:
            raise SystemExit(f"duplicate negative mutation {vector['mutation']}")
        seen_mutations.add(vector["mutation"])
        actual = negative_results.get(vector["mutation"])
        if actual is None:
            raise SystemExit(f"{vector['id']}: unknown mutation {vector['mutation']}")
        if actual != vector["expected_error"]:
            raise SystemExit(f"{vector['id']}: {actual} != {vector['expected_error']}")
    if seen_mutations != set(negative_results):
        raise SystemExit("approval pack must pin every required negative mutation")

    print(
        f"verified approval vectors: {len(index['assertions'])} signatures, "
        f"{len(index['cases'])} quorum cases, {len(index['negative_vectors'])} negative cases"
    )


if __name__ == "__main__":
    main()
