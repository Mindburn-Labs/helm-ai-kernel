#!/usr/bin/env python3
"""Independent offline update-bundle vector verifier.

Format + verifier only: no build tooling, no OTA mechanism. The tar.gz is
reconstructed from the payloads/ files by both verifiers; the manifest is the
signed trust anchor.

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


def signing_payload_text(manifest):
    working = copy.deepcopy(manifest)
    working["record_hash"] = ""
    working["signature"] = ""
    return canonical_json(working)


def verify_manifest(manifest, public_key_hex, expected_payload_text=None):
    if manifest.get("schema_version") != "update_bundle_manifest.v1":
        raise VectorError("contract_rejected", "unsupported update bundle contract")
    entries = manifest.get("entries", [])
    if not entries:
        raise VectorError("contract_rejected", "manifest carries no entries")
    if [entry["path"] for entry in entries] != sorted(entry["path"] for entry in entries):
        raise VectorError("contract_rejected", "manifest entries must be path-sorted")
    set_hash = sha256_ref(canonical_json(entries).encode("utf-8"))
    if set_hash != manifest.get("artifact_set_hash"):
        raise VectorError("set_hash_mismatch", f"entry set hash {set_hash} != {manifest.get('artifact_set_hash')}")
    payload = signing_payload_text(manifest)
    if expected_payload_text is not None and payload != expected_payload_text:
        raise VectorError("payload_mismatch", "recomputed signing payload differs from the golden payload")
    if sha256_ref(payload.encode("utf-8")) != manifest.get("record_hash"):
        raise VectorError("hash_mismatch", "manifest record hash mismatch")
    signature = prefixed_bytes(manifest.get("signature"), "ed25519:", 64)
    if not verify_ed25519(bytes.fromhex(public_key_hex), payload.encode("utf-8"), signature):
        raise VectorError("signature_rejected", "manifest signature verification failed")


def verify_payloads(index, manifest):
    by_path = {entry["path"]: entry for entry in manifest.get("entries", [])}
    seen = set()
    for vector in index["payloads"]:
        raw = (ROOT / vector["canonical"]).read_bytes()
        actual = sha256_ref(raw)
        if actual != vector["sha256"]:
            raise VectorError("payload_mismatch", f"{vector['canonical']}: {actual} != {vector['sha256']}")
        path = vector["canonical"].removeprefix("payloads/")
        entry = by_path.get(path)
        if entry is None:
            raise VectorError("payload_mismatch", f"{path} is not in the signed manifest")
        if entry["sha256"] != actual or entry["size"] != len(raw):
            raise VectorError("payload_mismatch", f"{path} does not match its manifest entry")
        seen.add(path)
    if seen != set(by_path):
        raise VectorError("payload_mismatch", "manifest entries and payload files diverge")


def run_negative(index, manifest):
    def expect(vector_id, fn):
        expected = next(v["expected_error"] for v in index["negative_vectors"] if v["id"] == vector_id)
        try:
            fn()
        except VectorError as error:
            if error.code != expected:
                raise VectorError("negative_vector_failed", f"{vector_id}: raised {error.code}, expected {expected}")
            return
        raise VectorError("negative_vector_failed", f"{vector_id}: mutation was accepted")

    public_key = index["public_key"]

    def signature_tamper():
        mutated = copy.deepcopy(manifest)
        sig = mutated["signature"]
        mutated["signature"] = sig[:-1] + ("0" if sig[-1] != "0" else "1")
        verify_manifest(mutated, public_key)

    def record_hash_tamper():
        mutated = copy.deepcopy(manifest)
        mutated["record_hash"] = sha256_ref(b"different bytes")
        verify_manifest(mutated, public_key)

    def entry_hash_flip():
        mutated = copy.deepcopy(manifest)
        mutated["entries"][0]["sha256"] = sha256_ref(b"flipped entry")
        verify_manifest(mutated, public_key)

    def payload_tamper():
        mutated_index = copy.deepcopy(index)
        for vector in mutated_index["payloads"]:
            if vector["canonical"] == "payloads/notes/README.txt":
                raw = (ROOT / vector["canonical"]).read_bytes() + b"#"
                vector["sha256"] = sha256_ref(raw)
        verify_payloads(mutated_index, manifest)

    def size_lie():
        mutated = copy.deepcopy(manifest)
        mutated["entries"][0]["size"] += 1
        verify_manifest(mutated, public_key)

    def kernel_version_substitution():
        mutated = copy.deepcopy(manifest)
        mutated["kernel_version"] = "9.9.9"
        verify_manifest(mutated, public_key)

    expect("signature_tamper", signature_tamper)
    expect("record_hash_tamper", record_hash_tamper)
    expect("entry_hash_flip", entry_hash_flip)
    expect("payload_tamper", payload_tamper)
    expect("size_lie", size_lie)
    expect("kernel_version_substitution", kernel_version_substitution)


def main():
    index_text = (ROOT / "vectors.json").read_text(encoding="utf-8").removesuffix("\n")
    index = json.loads(index_text)
    if canonical_json(index) != index_text:
        raise VectorError("canonical_mismatch", "vectors.json is not canonical JSON")
    if index.get("schema_version") != "update_bundle_vectors.v1":
        raise VectorError("contract_rejected", "unsupported vector pack version")
    manifest, _ = load_canonical(ROOT, index["manifest"])
    # c14n pins hash the newline-stripped canonical text (load_canonical
    # convention).
    payload_raw = (ROOT / index["signing_payload"]["canonical"]).read_bytes().removesuffix(b"\n")
    if sha256_ref(payload_raw) != index["signing_payload"]["sha256"]:
        raise VectorError("hash_mismatch", "signing payload file hash mismatch")
    verify_manifest(manifest, index["public_key"], payload_raw.decode("utf-8"))
    verify_payloads(index, manifest)
    run_negative(index, manifest)
    print("update-bundle-v1: all positive and negative vectors verified (independent Python implementation)")


if __name__ == "__main__":
    try:
        main()
    except VectorError as error:
        print(f"update-bundle-v1 verification FAILED [{error.code}]: {error}", file=sys.stderr)
        sys.exit(1)
