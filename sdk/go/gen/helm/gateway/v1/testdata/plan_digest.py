#!/usr/bin/env python3
"""Independent reference for the plan digest of docs/architecture/
gateway-provisioning-api.md: the lower-case hex SHA-256 of the RFC 8785 (JCS)
form of a provision or narrow plan without base_plan_digest. authority_admin_
contract_test.go runs it and compares its output with the Go reference.

For the ASCII strings and integers the plans carry, JCS is compact JSON with
the object members sorted by name (UTF-16 code units, which are code points
for ASCII), and that is what json.dumps writes here. Stdlib only.

quantum_posture: computes SHA-256 test vectors; signs or verifies nothing.
"""
import hashlib
import json
import os
import sys


def plan_digest(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k != "base_plan_digest"}
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main():
    root = sys.argv[1]
    path = os.path.join(root, "protocols/json-schemas/effects/authority/examples/provision.v1.valid.json")
    with open(path, encoding="utf-8") as f:
        plan = json.load(f)
    # The digest ignores base_plan_digest, whatever it holds.
    other = dict(plan, base_plan_digest="f" * 64)
    print(json.dumps({"digest": plan_digest(plan), "with_other_base": plan_digest(other)}))


if __name__ == "__main__":
    main()
