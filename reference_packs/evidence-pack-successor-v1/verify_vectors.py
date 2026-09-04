#!/usr/bin/env python3
"""Verify EvidencePack successor identities, hashes, and ProofGraph lineage."""

import copy
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NODE_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = {
    "OPERATIONAL_EVALUATION",
    "MEASUREMENT_PROGRESS",
    "MEASUREMENT_FINAL",
    "MEASUREMENT_CENSORED",
}
SUCCESSOR_KEYS = {
    "schema_version",
    "contract_version",
    "successor_id",
    "kind",
    "predecessor_ref",
    "predecessor_hash",
    "sealed_pack_ref",
    "sealed_pack_hash",
    "lineage",
    "evidence_ref",
    "evidence_hash",
    "recorded_at",
    "successor_hash",
}
LINEAGE_KEYS = {
    "schema_version",
    "tenant_id",
    "company_id",
    "workspace_id",
    "environment_id",
    "activation_record_ref",
    "activation_record_hash",
    "outcome_contract_ref",
    "outcome_contract_hash",
    "measurement_plan_ref",
    "measurement_plan_hash",
    "window_identity",
}


class VectorError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def canonical_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256_ref(payload):
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def require_sha(value, field):
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise VectorError("contract_rejected", f"invalid {field}")


def require_token(value, field):
    if not isinstance(value, str) or not value or len(value) > 512 or any(character.isspace() for character in value):
        raise VectorError("contract_rejected", f"invalid {field}")


def load_canonical(filename):
    raw = (ROOT / filename).read_bytes()
    value = json.loads(raw)
    if raw != (canonical_json(value) + "\n").encode("utf-8"):
        raise VectorError("canonical_mismatch", filename)
    return value, raw[:-1]


def validate_lineage(lineage):
    if not isinstance(lineage, dict) or set(lineage) != LINEAGE_KEYS:
        raise VectorError("contract_rejected", "lineage fields")
    if lineage["schema_version"] != "evidence-pack-lineage.v1":
        raise VectorError("contract_rejected", "lineage schema")
    for field in (
        "tenant_id",
        "company_id",
        "workspace_id",
        "environment_id",
        "activation_record_ref",
        "outcome_contract_ref",
        "measurement_plan_ref",
        "window_identity",
    ):
        require_token(lineage[field], field)
    if lineage["company_id"] != lineage["tenant_id"]:
        raise VectorError("contract_rejected", "company tenant scope")
    for field in ("activation_record_hash", "outcome_contract_hash", "measurement_plan_hash"):
        require_sha(lineage[field], field)


def successor_identity(successor):
    contract_hash = (
        successor["lineage"]["outcome_contract_hash"]
        if successor["kind"] == "OPERATIONAL_EVALUATION"
        else successor["lineage"]["measurement_plan_hash"]
    )
    identity = {
        "schema_version": successor["schema_version"],
        "contract_version": successor["contract_version"],
        "predecessor_hash": successor["predecessor_hash"],
        "kind": successor["kind"],
        "contract_hash": contract_hash,
        "window_identity": successor["lineage"]["window_identity"],
    }
    return sha256_ref(canonical_json(identity).encode("utf-8"))


def successor_hash(successor):
    unsigned = dict(successor)
    unsigned["successor_hash"] = ""
    return sha256_ref(canonical_json(unsigned).encode("utf-8"))


def reseal_successor(successor):
    successor["successor_id"] = successor_identity(successor)
    successor["successor_hash"] = successor_hash(successor)


def validate_successor(successor):
    if not isinstance(successor, dict) or set(successor) != SUCCESSOR_KEYS:
        raise VectorError("contract_rejected", "successor fields")
    if successor["schema_version"] != "evidence-pack-successor.v1" or successor["contract_version"] != "2026-09-04":
        raise VectorError("contract_rejected", "successor version")
    if successor["kind"] not in KINDS:
        raise VectorError("contract_rejected", "successor kind")
    for field in ("predecessor_ref", "sealed_pack_ref", "evidence_ref"):
        require_token(successor[field], field)
    for field in ("successor_id", "predecessor_hash", "sealed_pack_hash", "evidence_hash", "successor_hash"):
        require_sha(successor[field], field)
    validate_lineage(successor["lineage"])
    if successor["successor_id"] != successor_identity(successor):
        raise VectorError("successor_id_mismatch", "successor identity")
    if successor["successor_hash"] != successor_hash(successor):
        raise VectorError("successor_hash_mismatch", "successor content")


def node_hash(node):
    hashable = {
        "kind": node["kind"],
        "parents": node["parents"],
        "lamport": node["lamport"],
        "principal": node["principal"],
        "principal_seq": node["principal_seq"],
        "payload": node["payload"],
        "sig": node["sig"],
    }
    if node.get("sig_purpose"):
        hashable["sig_purpose"] = node["sig_purpose"]
    return hashlib.sha256(canonical_json(hashable).encode("utf-8")).hexdigest()


def validate_node(node):
    if node.get("kind") != "ATTESTATION" or not NODE_HASH_RE.fullmatch(node.get("node_hash", "")):
        raise VectorError("proofgraph_rejected", "node type or hash")
    if node["node_hash"] != node_hash(node):
        raise VectorError("proofgraph_hash_mismatch", node["node_hash"])


def validate_chain(nodes, expected_hashes, expected_kinds):
    if [node.get("node_hash") for node in nodes] != expected_hashes:
        raise VectorError("proofgraph_chain_mismatch", "declared node order")
    if len(nodes) != len(expected_kinds) + 1:
        raise VectorError("proofgraph_chain_mismatch", "chain length")
    seen = set()
    root = nodes[0]
    validate_node(root)
    root_payload = root["payload"]
    if set(root_payload) != {"schema_version", "sealed_pack_ref", "sealed_pack_hash", "lineage"}:
        raise VectorError("contract_rejected", "root fields")
    if root_payload["schema_version"] != "proofgraph-evidence-pack-lineage-root.v1":
        raise VectorError("contract_rejected", "root schema")
    require_token(root_payload["sealed_pack_ref"], "root sealed_pack_ref")
    require_sha(root_payload["sealed_pack_hash"], "root sealed_pack_hash")
    validate_lineage(root_payload["lineage"])
    seen.add(root["node_hash"])
    previous_payload = root_payload

    for index, node in enumerate(nodes[1:]):
        validate_node(node)
        if node.get("parents") != [nodes[index]["node_hash"]]:
            parent = node.get("parents", [None])[0] if node.get("parents") else None
            if parent not in seen:
                raise VectorError("dangling_predecessor", str(parent))
            raise VectorError("proofgraph_chain_mismatch", "wrong parent")
        successor = node["payload"]
        validate_successor(successor)
        if successor["kind"] != expected_kinds[index]:
            raise VectorError("transition_rejected", successor["kind"])
        if successor["lineage"] != root_payload["lineage"] or successor["sealed_pack_ref"] != root_payload["sealed_pack_ref"] or successor["sealed_pack_hash"] != root_payload["sealed_pack_hash"]:
            raise VectorError("lineage_conflict", "frozen identity changed")
        expected_ref = previous_payload["sealed_pack_ref"] if index == 0 else previous_payload["successor_id"]
        expected_hash = previous_payload["sealed_pack_hash"] if index == 0 else previous_payload["successor_hash"]
        if successor["predecessor_ref"] != expected_ref or successor["predecessor_hash"] != expected_hash:
            raise VectorError("lineage_conflict", "predecessor binding")
        previous_payload = successor
        seen.add(node["node_hash"])


def negative_result(vector, artifacts, final_nodes):
    mutation = vector["mutation"]
    try:
        if mutation == "add_unknown_successor_field":
            candidate = copy.deepcopy(artifacts["operational_evaluation"])
            candidate["unknown_authority"] = True
            validate_successor(candidate)
        elif mutation == "replace_outcome_contract_hash_and_reseal":
            candidate = copy.deepcopy(artifacts["measurement_progress"])
            candidate["lineage"]["outcome_contract_hash"] = sha256_ref(b"substituted-outcome")
            reseal_successor(candidate)
            validate_successor(candidate)
            if candidate["lineage"] != artifacts["operational_evaluation"]["lineage"]:
                raise VectorError("lineage_conflict", "frozen identity changed")
        elif mutation == "replace_evidence_hash_without_changing_identity":
            candidate = copy.deepcopy(artifacts["measurement_progress"])
            candidate["evidence_hash"] = sha256_ref(b"conflicting-evidence")
            validate_successor(candidate)
        elif mutation == "set_progress_kind_to_measurement_final_without_reseal":
            candidate = copy.deepcopy(artifacts["measurement_progress"])
            candidate["kind"] = "MEASUREMENT_FINAL"
            validate_successor(candidate)
        elif mutation == "append_censored_after_final":
            validate_successor(artifacts["measurement_censored"])
            if artifacts["measurement_final"]["kind"] in {"MEASUREMENT_FINAL", "MEASUREMENT_CENSORED"}:
                raise VectorError("measurement_closed", "second terminal addendum")
        elif mutation == "replace_proofgraph_parent_with_unknown_hash":
            nodes = copy.deepcopy(final_nodes)
            nodes[-1]["parents"] = ["f" * 64]
            nodes[-1]["node_hash"] = node_hash(nodes[-1])
            hashes = [node["node_hash"] for node in nodes]
            validate_chain(nodes, hashes, ["OPERATIONAL_EVALUATION", "MEASUREMENT_PROGRESS", "MEASUREMENT_FINAL"])
        else:
            raise VectorError("unknown_mutation", mutation)
    except VectorError as error:
        return error.code
    return "accepted"


def main():
    vectors = json.loads((ROOT / "vectors.json").read_text(encoding="utf-8"))
    if vectors.get("schema_version") != "evidence-pack-successor-vectors.v1" or vectors.get("contract_version") != "2026-09-04":
        raise VectorError("vector_index_rejected", "version")

    artifacts = {}
    role_values = {}
    for item in vectors["files"]:
        value, canonical = load_canonical(item["canonical"])
        if sha256_ref(canonical) != item["sha256"]:
            raise VectorError("file_hash_mismatch", item["canonical"])
        role_values[item["role"]] = value
        if item["role"] in {"operational_evaluation", "measurement_progress", "measurement_final", "measurement_censored"}:
            validate_successor(value)
            artifacts[item["role"]] = value

    final_nodes = role_values["proofgraph_final_chain"]
    validate_chain(
        final_nodes,
        vectors["final_node_chain"],
        ["OPERATIONAL_EVALUATION", "MEASUREMENT_PROGRESS", "MEASUREMENT_FINAL"],
    )
    validate_chain(
        role_values["proofgraph_censored_chain"],
        vectors["censored_node_chain"],
        ["OPERATIONAL_EVALUATION", "MEASUREMENT_CENSORED"],
    )

    for vector in vectors["negative_vectors"]:
        result = negative_result(vector, artifacts, final_nodes)
        if result != vector["expected_error"]:
            raise VectorError("negative_vector_failed", f"{vector['id']}: got {result}, want {vector['expected_error']}")

    print(
        "EvidencePack successor vectors verified: "
        f"{len(vectors['files'])} canonical files, "
        f"{len(vectors['final_node_chain']) + len(vectors['censored_node_chain'])} ProofGraph nodes, "
        f"{len(vectors['negative_vectors'])} negative mutations"
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, VectorError) as error:
        print(f"EvidencePack successor vector verification failed: {error}", file=sys.stderr)
        raise SystemExit(1)
