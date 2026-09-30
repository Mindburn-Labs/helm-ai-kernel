#!/usr/bin/env python3
"""Independent reference for the plan digest of docs/architecture/
gateway-provisioning-api.md: the lower-case hex SHA-256 of the RFC 8785 (JCS)
form of a provision or narrow plan without base_plan_digest.
authority_admin_contract_test.go runs it and compares its output with the Go
reference.

The form is written out here rather than delegated to json.dumps: object
members sort by their UTF-16 code units, strings are written as ES6
JSON.stringify writes them (only the quote, the backslash and the control
characters are escaped, so "&", "<", ">", non-ASCII text and U+2028 stay as
they are), and the integers a plan carries keep their digits. Stdlib only.

quantum_posture: computes SHA-256 test vectors; signs or verifies nothing.
"""
import hashlib
import json
import os
import sys

EXAMPLES = "protocols/json-schemas/effects/authority/examples"


def jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("a plan carries no fractional number")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in keys) + "}"
    raise TypeError(type(value))


def plan_digest(plan: dict) -> str:
    body = {k: v for k, v in plan.items() if k != "base_plan_digest"}
    return hashlib.sha256(jcs(body).encode("utf-8")).hexdigest()


def load(root: str, name: str) -> dict:
    with open(os.path.join(root, EXAMPLES, name), encoding="utf-8") as f:
        return json.load(f)


def main():
    root = sys.argv[1]
    plan = load(root, "provision.v1.valid.json")
    escapes = load(root, "provision.v1.valid-escapes.json")
    # The digest ignores base_plan_digest, whatever it holds.
    other = dict(plan, base_plan_digest="f" * 64)
    print(json.dumps({
        "digest": plan_digest(plan),
        "with_other_base": plan_digest(other),
        "escapes": plan_digest(escapes),
    }))


if __name__ == "__main__":
    main()
