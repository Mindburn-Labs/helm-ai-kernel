#!/usr/bin/env python3
"""Independent Boundary Enforcement Profile vector verifier.

HELM compiles OS enforcement artifacts and attests posture; the OS enforces.
Fail closed on drift. This verifier re-derives every hash, signature, and
binding in the pack without the Go implementation.

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
    prefixed_bytes,
    sha256_ref,
    verify_ed25519,
)

ROOT = Path(__file__).resolve().parent

NFT_TABLE = "table inet helm_boundary"


def normalize_nft_ruleset(text):
    """Mirror of Go profile.NormalizeNftRuleset: comments, blank lines,
    brace-only lines and the table declare/delete preamble drop out; each
    remaining line is whitespace-trimmed with any trailing "{" removed."""
    keep = []
    for line in text.split("\n"):
        t = line.strip()
        if not t or t.startswith("#"):
            continue
        if t.endswith("{"):
            t = t[:-1].strip()
        if not t or t == "}" or t in (NFT_TABLE, "delete " + NFT_TABLE):
            continue
        keep.append(t)
    return "\n".join(keep)


def load_raw(descriptor):
    """Load a c14n signing-payload file: pins hash the newline-stripped
    canonical text (same convention as load_canonical)."""
    raw = (ROOT / descriptor["canonical"]).read_bytes().removesuffix(b"\n")
    actual = sha256_ref(raw)
    if actual != descriptor["sha256"]:
        raise VectorError("hash_mismatch", f"{descriptor['canonical']}: {actual} != {descriptor['sha256']}")
    return raw


def signing_payload_text(record, drop_signature_key):
    working = copy.deepcopy(record)
    working["record_hash"] = ""
    if drop_signature_key:
        working.pop("signature", None)
    else:
        working["signature"] = ""
    return canonical_json(working)


def verify_compile_receipt(receipt, public_key_hex, expected_payload_text=None):
    if receipt.get("schema_version") != "profile_compile_receipt.v1":
        raise VectorError("contract_rejected", "unsupported compile receipt contract")
    if receipt.get("mode_tier") not in ("observe", "enforce"):
        raise VectorError("contract_rejected", "invalid mode tier")
    payload = signing_payload_text(receipt, drop_signature_key=False)
    if expected_payload_text is not None and payload != expected_payload_text:
        raise VectorError("payload_mismatch", "recomputed signing payload differs from the golden payload")
    if sha256_ref(payload.encode("utf-8")) != receipt.get("record_hash"):
        raise VectorError("hash_mismatch", "compile receipt record hash mismatch")
    signature = prefixed_bytes(receipt.get("signature"), "ed25519:", 64)
    public_key = bytes.fromhex(public_key_hex)
    if not verify_ed25519(public_key, payload.encode("utf-8"), signature):
        raise VectorError("signature_rejected", "compile receipt signature verification failed")


def verify_input_binding(profile_input, receipt, input_text):
    if profile_input.get("schema_version") != "boundary_profile_input.v1":
        raise VectorError("contract_rejected", "unsupported profile input contract")
    actual = sha256_ref(input_text.encode("utf-8"))
    if actual != receipt.get("policy_input_hash"):
        raise VectorError("input_hash_mismatch", f"profile input hash {actual} != {receipt.get('policy_input_hash')}")


def verify_artifact_set(index, receipt):
    by_path = {ref["path"]: ref["sha256"] for ref in receipt.get("artifacts", [])}
    if len(by_path) != len(receipt.get("artifacts", [])):
        raise VectorError("artifact_mismatch", "duplicate artifact paths in receipt")
    recomputed = []
    for vector in index["artifacts"]:
        raw = (ROOT / vector["canonical"]).read_bytes()
        actual = sha256_ref(raw)
        if actual != vector["sha256"]:
            raise VectorError("artifact_mismatch", f"{vector['canonical']}: {actual} != {vector['sha256']}")
        if by_path.get(vector["path"]) != actual:
            raise VectorError("artifact_mismatch", f"{vector['path']} not bound by the compile receipt")
        recomputed.append({"path": vector["path"], "sha256": actual})
    recomputed.sort(key=lambda ref: ref["path"])
    if [ref["path"] for ref in recomputed] != sorted(by_path):
        raise VectorError("artifact_mismatch", "artifact set differs from the receipt reference list")
    set_hash = sha256_ref(canonical_json(recomputed).encode("utf-8"))
    if set_hash != receipt.get("artifact_set_hash"):
        raise VectorError("artifact_mismatch", f"artifact set hash {set_hash} != {receipt.get('artifact_set_hash')}")


def verify_attestation(attestation, receipt, public_key_hex=None, signature_required=False, expected_payload_text=None):
    if attestation.get("schema_version") != "posture_attestation.v1":
        raise VectorError("contract_rejected", "unsupported posture attestation contract")
    if attestation.get("receipt_hash") != receipt.get("record_hash") or attestation.get("receipt_id") != receipt.get("receipt_id"):
        raise VectorError("binding_mismatch", "attestation is bound to a different compile receipt")
    checks = attestation.get("checks", [])
    if not checks:
        raise VectorError("contract_rejected", "attestation carries no checks")
    fails = [check for check in checks if check.get("result") == "FAIL"]
    verdict = attestation.get("verdict")
    if verdict == "MATCH" and fails:
        raise VectorError("verdict_inconsistent", "MATCH attestation carries failed checks")
    if verdict == "DRIFT" and not fails:
        raise VectorError("verdict_inconsistent", "DRIFT attestation carries no failed checks")
    if verdict not in ("MATCH", "DRIFT"):
        raise VectorError("verdict_inconsistent", f"unknown verdict {verdict!r}")
    has_signature = "signature" in attestation
    payload = signing_payload_text(attestation, drop_signature_key=True)
    if expected_payload_text is not None and payload != expected_payload_text:
        raise VectorError("payload_mismatch", "recomputed attestation payload differs from the golden payload")
    if sha256_ref(payload.encode("utf-8")) != attestation.get("record_hash"):
        raise VectorError("hash_mismatch", "posture attestation record hash mismatch")
    if signature_required and not has_signature:
        raise VectorError("signature_rejected", "attestation signature is required")
    if has_signature:
        signature = prefixed_bytes(attestation["signature"], "ed25519:", 64)
        if not verify_ed25519(bytes.fromhex(public_key_hex), payload.encode("utf-8"), signature):
            raise VectorError("signature_rejected", "posture attestation signature verification failed")
    return fails


def verify_ruleset_normalization():
    expected_posture = json.loads((ROOT / "artifacts/posture/expected_posture.json").read_text(encoding="utf-8"))
    ruleset = (ROOT / "artifacts/nftables/helm-boundary.nft").read_text(encoding="utf-8")
    actual = sha256_ref(normalize_nft_ruleset(ruleset).encode("utf-8"))
    pinned = expected_posture["nftables"]["ruleset_sha256"]
    if actual != pinned:
        raise VectorError("ruleset_normalization_mismatch", f"normalized ruleset hash {actual} != {pinned}")


def run_positive(index):
    profile_input, input_text = load_canonical(ROOT, index["profile_input"])
    receipt, _ = load_canonical(ROOT, index["compile_receipt"]["artifact"])
    receipt_payload = load_raw(index["compile_receipt"]["signing_payload"]).decode("utf-8").removesuffix("\n")
    match, _ = load_canonical(ROOT, index["attestation_match"]["artifact"])
    match_payload = load_raw(index["attestation_match"]["signing_payload"]).decode("utf-8").removesuffix("\n")
    drift, _ = load_canonical(ROOT, index["attestation_drift"])

    verify_compile_receipt(receipt, index["compile_receipt"]["public_key"], receipt_payload)
    verify_input_binding(profile_input, receipt, input_text)
    verify_artifact_set(index, receipt)
    fails = verify_attestation(match, receipt, index["attestation_match"]["public_key"], signature_required=True, expected_payload_text=match_payload)
    if fails:
        raise VectorError("verdict_inconsistent", "golden MATCH attestation must have no failures")
    drift_fails = verify_attestation(drift, receipt)
    diff = [check for check in drift_fails if check.get("property") == "NoNewPrivileges"]
    if not diff or diff[0].get("expected") != "yes" or diff[0].get("observed") != "no":
        raise VectorError("verdict_inconsistent", "golden DRIFT attestation must record the loosened rule diff")
    verify_ruleset_normalization()
    return receipt, profile_input, match, drift


def run_negative(index, receipt, profile_input, match, drift):
    def expect(vector_id, fn):
        expected = next(v["expected_error"] for v in index["negative_vectors"] if v["id"] == vector_id)
        try:
            fn()
        except VectorError as error:
            if error.code != expected:
                raise VectorError("negative_vector_failed", f"{vector_id}: raised {error.code}, expected {expected}")
            return
        raise VectorError("negative_vector_failed", f"{vector_id}: mutation was accepted")

    public_key = index["compile_receipt"]["public_key"]

    def signature_tamper():
        mutated = copy.deepcopy(receipt)
        sig = mutated["signature"]
        mutated["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        verify_compile_receipt(mutated, public_key)

    def record_hash_tamper():
        mutated = copy.deepcopy(receipt)
        mutated["record_hash"] = sha256_ref(b"different bytes")
        verify_compile_receipt(mutated, public_key)

    def tier_substitution():
        mutated = copy.deepcopy(receipt)
        mutated["mode_tier"] = "observe"
        verify_compile_receipt(mutated, public_key)

    def artifact_set_substitution():
        mutated = copy.deepcopy(receipt)
        mutated["artifact_set_hash"] = sha256_ref(b"another artifact set")
        verify_compile_receipt(mutated, public_key)

    def artifact_content_tamper():
        mutated_index = copy.deepcopy(index)
        for vector in mutated_index["artifacts"]:
            if vector["path"] == "nftables/helm-boundary.nft":
                raw = (ROOT / vector["canonical"]).read_bytes() + b"#"
                vector["sha256"] = sha256_ref(raw)
        verify_artifact_set(mutated_index, receipt)

    def input_substitution():
        mutated = copy.deepcopy(profile_input)
        mutated["mode_tier"] = "observe"
        verify_input_binding(mutated, receipt, canonical_json(mutated))

    def drift_reported_as_match():
        mutated = copy.deepcopy(drift)
        mutated["verdict"] = "MATCH"
        verify_attestation(mutated, receipt)

    def attestation_receipt_unbound():
        mutated = copy.deepcopy(match)
        mutated["receipt_hash"] = sha256_ref(b"another receipt")
        verify_attestation(mutated, receipt, public_key, signature_required=True)

    expect("signature_tamper", signature_tamper)
    expect("record_hash_tamper", record_hash_tamper)
    expect("tier_substitution", tier_substitution)
    expect("artifact_set_substitution", artifact_set_substitution)
    expect("artifact_content_tamper", artifact_content_tamper)
    expect("input_substitution", input_substitution)
    expect("drift_reported_as_match", drift_reported_as_match)
    expect("attestation_receipt_unbound", attestation_receipt_unbound)


def main():
    index_text = (ROOT / "vectors.json").read_text(encoding="utf-8").removesuffix("\n")
    index = json.loads(index_text)
    if canonical_json(index) != index_text:
        raise VectorError("canonical_mismatch", "vectors.json is not canonical JSON")
    if index.get("schema_version") != "boundary_profile_vectors.v1":
        raise VectorError("contract_rejected", "unsupported vector pack version")
    receipt, profile_input, match, drift = run_positive(index)
    run_negative(index, receipt, profile_input, match, drift)
    print("boundary-profile-v1: all positive and negative vectors verified (independent Python implementation)")


if __name__ == "__main__":
    try:
        main()
    except VectorError as error:
        print(f"boundary-profile-v1 verification FAILED [{error.code}]: {error}", file=sys.stderr)
        sys.exit(1)
