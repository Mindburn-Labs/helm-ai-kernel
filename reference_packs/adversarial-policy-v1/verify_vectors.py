#!/usr/bin/env python3
"""Independent verifier for reference_packs/adversarial-policy-v1.

Encodes the fail-closed policy table from docs/governance/ (capability
registry, reversibility classes, task capability tokens, memory governance,
model routing) as executable rules, then checks every vector's expected
decision against the rule output.

Scope honesty: this verifies vector <-> policy-table consistency. It does NOT
drive the Go guardian; guardian-wired replay is follow-up work.

Exit 0 = all vectors consistent. Exit 1 = at least one violation.
"""

import json
import sys
from pathlib import Path

PACK_DIR = Path(__file__).resolve().parent
DOCS = (
    "docs/governance/capability-registry.md",
    "docs/governance/reversibility-classes.md",
    "docs/governance/task-capability-tokens.md",
    "docs/governance/memory-governance.md",
    "docs/governance/model-routing-policy.md",
)

TERMINAL_TOKEN_STATES = {"used_up", "expired", "revoked"}
NON_READ_ONLY = {
    "write_local",
    "write_external",
    "network_egress",
    "credential_access",
    "code_execution",
    "financial",
    "irreversible",
}
# model-routing-policy.md rule 1 tier ceilings (fast_edge may never plan these)
FAST_EDGE_FORBIDDEN = {"financial", "credential_access", "irreversible"}


def decide(inputs: dict) -> tuple[str, str]:
    """Executable policy table. Order matters: first matching rule wins."""
    # capability-registry.md: unknown capability = fail closed via quarantine
    if not inputs.get("capability_registered", False):
        return "ESCALATE", "unknown_capability_quarantine"

    # task-capability-tokens.md: manifest drift invalidates tokens, fail closed
    if inputs.get("token_status") not in (None, "none") and not inputs.get(
        "manifest_hash_match", True
    ):
        return "DENY", "manifest_drift_fail_closed"

    # task-capability-tokens.md: terminal token states refuse dispatch
    if inputs.get("token_status") in TERMINAL_TOKEN_STATES:
        return "DENY", "capability_token_terminal_state"

    # task binding: effects outside the task scope fail closed
    if not inputs.get("task_bound", False):
        return "DENY", "effect_outside_task_scope"

    # reversibility-classes.md rule 1: no plan, no dispatch
    if (
        inputs.get("reversibility") in ("compensating_action", "exact_undo")
        and inputs.get("effect_class") in NON_READ_ONLY
        and not inputs.get("rollback_plan_present", True)
    ):
        return "DENY", "rollback_plan_required"

    # reversibility-classes.md rule 3: rollback claims on irreversible effects
    # are unverifiable and must not be silently honored
    if inputs.get("reversibility") == "none" and inputs.get(
        "rollback_plan_present", False
    ):
        return "ESCALATE", "rollback_claim_unverifiable"

    # memory-governance.md rule: cross-domain reads are deny by default
    if inputs.get("cross_domain_read") and not inputs.get(
        "cross_domain_granted", False
    ):
        return "DENY", "cross_domain_memory_read_denied"

    # memory-governance.md rule 2: deletable memory must produce receipts
    if inputs.get("deletion_receipt_produced") is False:
        return "DENY", "deletion_receipt_required"

    # memory-governance.md rule 3: derived memory inherits classification
    if (
        inputs.get("derived_from_user_domain")
        and inputs.get("data_boundary") == "external"
        and not inputs.get("declassification_receipt", True)
    ):
        return "DENY", "derived_memory_boundary_violation"

    # model-routing-policy.md rule 1: tier ceilings are evaluated before
    # approval — a forbidden-tier plan never reaches approval evaluation
    if (
        inputs.get("model_tier") == "fast_edge"
        and inputs.get("effect_class") in FAST_EDGE_FORBIDDEN
    ):
        return "ESCALATE", "model_tier_ceiling_exceeded"

    # permit-bearing effects need a valid approval artifact
    if not inputs.get("approval_valid", True):
        if inputs.get("effect_class") in ("financial", "credential_access"):
            return "DENY", "approval_artifact_invalid"

    return "ALLOW", "within_policy"


def main() -> int:
    vectors_path = PACK_DIR / "vectors.json"
    pack = json.loads(vectors_path.read_text(encoding="utf-8"))
    if pack.get("schema_version") != "adversarial-policy-vectors/v1":
        print("FAIL: unexpected schema_version", file=sys.stderr)
        return 1

    repo_root = PACK_DIR.parent.parent
    missing_docs = [d for d in DOCS if not (repo_root / d).exists()]
    if missing_docs:
        print(f"FAIL: policy docs missing: {missing_docs}", file=sys.stderr)
        return 1

    failures = 0
    for vector in pack["vectors"]:
        for key in ("id", "category", "narrative", "inputs", "expected"):
            if key not in vector:
                print(f"FAIL: {vector.get('id', '?')} missing key {key}")
                failures += 1
                continue
        decision, reason = decide(vector["inputs"])
        expected = vector["expected"]
        ok = decision == expected["decision"] and reason == expected["reason_code"]
        status = "ok" if ok else "FAIL"
        print(
            f"{status}: {vector['id']} [{vector['category']}] "
            f"expected {expected['decision']}/{expected['reason_code']} "
            f"got {decision}/{reason}"
        )
        if not ok:
            failures += 1

    if failures:
        print(f"\n{failures} vector(s) inconsistent with policy table", file=sys.stderr)
        return 1
    print(f"\nAll {len(pack['vectors'])} vectors consistent with policy table.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
