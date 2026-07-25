#!/usr/bin/env python3
"""Validate the reason-code registry against its own JSON Schema.

The registry is schema *input*, not a schema, so check_json_schemas.py only
parsed it — nothing ever validated the entries. The schema's `domain` enum
drifted until 74 of 96 entries were invalid against it (HELM-374).

Deliberately stdlib-only: CI installs no jsonschema package, and
check_json_schemas.py's optional `import jsonschema` — which silently degrades
to a parse-only pass when absent — is how this drift survived review. A checker
that can no-op is not a gate.

The whole document is walked from the schema root, so a constraint added
anywhere — root, `codes`, an entry, a `$defs` target — is either enforced or
reported. Any keyword outside ENFORCED/ANNOTATIONS is a hard failure rather
than a silent skip, so tightening the schema forces this checker to keep up.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "protocols/json-schemas/reason-codes/reason-codes-v1.schema.json"
REGISTRY_PATH = ROOT / "protocols/json-schemas/reason-codes/reason-codes-v1.json"

# The 2020-12 core and annotation vocabularies: none of these assert anything
# about an instance, so ignoring them is not a coverage gap. `$defs` only holds
# targets reached through `$ref`. Assertion and applicator keywords are
# deliberately absent — an unlisted one must fail, not be assumed harmless.
ANNOTATIONS = {
    "$schema", "$id", "$defs", "$comment",
    "title", "description", "default", "examples", "deprecated", "readOnly", "writeOnly",
}
ENFORCED = {"$ref", "type", "const", "enum", "pattern", "properties", "required", "items", "minItems"}
TYPES = {"object": dict, "array": list, "string": str}


def validate(where: str, value: Any, spec: dict[str, Any], root: dict[str, Any], out: list[str]) -> None:
    unenforced = set(spec) - ENFORCED - ANNOTATIONS
    if unenforced:
        out.append(f"{where}: schema keyword(s) {sorted(unenforced)} are not enforced by {Path(__file__).name}")
        return

    # 2020-12 allows `$ref` siblings, so apply the target and then the rest.
    ref = spec.get("$ref")
    if ref is not None:
        name = ref.removeprefix("#/$defs/")
        target = root.get("$defs", {}).get(name)
        if name == ref or not isinstance(target, dict):
            out.append(f"{where}: cannot resolve {ref!r}; only '#/$defs/<name>' is supported")
            return
        validate(where, value, target, root, out)

    declared = spec.get("type")
    if declared is not None:
        expected = TYPES.get(declared)
        if expected is None:
            out.append(f"{where}: schema type {declared!r} is not enforced by {Path(__file__).name}")
            return
        if not isinstance(value, expected):
            out.append(f"{where}: expected {declared}, got {type(value).__name__}")
            return

    if "const" in spec and value != spec["const"]:
        out.append(f"{where}: expected {spec['const']!r}, got {value!r}")
    if "enum" in spec and value not in spec["enum"]:
        out.append(f"{where}: {value!r} is not one of {spec['enum']}")
    if "pattern" in spec and not (isinstance(value, str) and re.search(spec["pattern"], value)):
        out.append(f"{where}: {value!r} does not match {spec['pattern']}")

    if isinstance(value, list):
        if len(value) < spec.get("minItems", 0):
            out.append(f"{where}: needs at least {spec['minItems']} item(s), got {len(value)}")
        if "items" in spec:
            for index, item in enumerate(value):
                label = item.get("code") if isinstance(item, dict) else None
                child = f"{where}[{index}]" + (f" ({label})" if isinstance(label, str) else "")
                validate(child, item, spec["items"], root, out)

    if isinstance(value, dict):
        for field in spec.get("required", []):
            if field not in value:
                out.append(f"{where}: missing required field {field!r}")
        for field, subspec in spec.get("properties", {}).items():
            if field in value:
                validate(f"{where}.{field}", value[field], subspec, root, out)


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))

    failures: list[str] = []
    validate("registry", registry, schema, schema, failures)

    if failures:
        print(f"reason-code registry does not validate against {SCHEMA_PATH.relative_to(ROOT)}:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    codes = registry.get("codes", [])
    print(f"reason-code registry check passed: {len(codes)} entries valid against the v1 schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
