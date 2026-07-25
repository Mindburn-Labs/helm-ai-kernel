#!/usr/bin/env python3
"""Validate the reason-code registry against its own JSON Schema.

The registry is schema *input*, not a schema, so check_json_schemas.py only
parsed it — nothing ever validated the entries. The schema's `domain` enum
drifted until 74 of 96 entries were invalid against it (HELM-374).

Deliberately stdlib-only: CI installs no jsonschema package, and
check_json_schemas.py's optional `import jsonschema` — which silently degrades
to a parse-only pass when absent — is how this drift survived review. A checker
that can no-op is not a gate.

Only the keywords the schema actually uses are enforced. Any other keyword is a
hard failure rather than a silent skip, so tightening the schema forces this
checker to keep up.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "protocols/json-schemas/reason-codes/reason-codes-v1.schema.json"
REGISTRY_PATH = ROOT / "protocols/json-schemas/reason-codes/reason-codes-v1.json"

# Annotations carry no constraint; ignoring them is not a coverage gap.
ANNOTATIONS = {"description", "title", "$ref", "$comment"}
ENFORCED = {"type", "const", "enum", "pattern", "items", "minItems"}


def validate(where: str, value: Any, spec: dict[str, Any], out: list[str]) -> None:
    unenforced = set(spec) - ENFORCED - ANNOTATIONS
    if unenforced:
        out.append(f"{where}: schema keyword(s) {sorted(unenforced)} are not enforced by {Path(__file__).name}")
        return

    declared = spec.get("type")
    if declared == "string" and not isinstance(value, str):
        out.append(f"{where}: expected string, got {type(value).__name__}")
        return
    if declared == "array" and not isinstance(value, list):
        out.append(f"{where}: expected array, got {type(value).__name__}")
        return

    if "const" in spec and value != spec["const"]:
        out.append(f"{where}: expected {spec['const']!r}, got {value!r}")
    if "enum" in spec and value not in spec["enum"]:
        out.append(f"{where}: {value!r} is not one of {spec['enum']}")
    if "pattern" in spec and not (isinstance(value, str) and re.search(spec["pattern"], value)):
        out.append(f"{where}: {value!r} does not match {spec['pattern']}")
    if "minItems" in spec and len(value) < spec["minItems"]:
        out.append(f"{where}: needs at least {spec['minItems']} item(s), got {len(value)}")
    if "items" in spec:
        for i, item in enumerate(value):
            validate(f"{where}[{i}]", item, spec["items"], out)


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    entry_schema = schema["$defs"]["ReasonCodeEntry"]
    properties = entry_schema["properties"]

    failures: list[str] = []
    validate("version", registry.get("version"), schema["properties"]["version"], failures)

    codes = registry.get("codes")
    if not isinstance(codes, list):
        failures.append("codes: expected array")
        codes = []

    for index, entry in enumerate(codes):
        label = entry.get("code") if isinstance(entry, dict) else None
        where = f"codes[{index}]" + (f" ({label})" if label else "")
        if not isinstance(entry, dict):
            failures.append(f"{where}: expected object")
            continue
        for field in entry_schema["required"]:
            if field not in entry:
                failures.append(f"{where}: missing required field {field!r}")
        for field, value in entry.items():
            if field in properties:
                validate(f"{where}.{field}", value, properties[field], failures)

    if failures:
        print(f"reason-code registry does not validate against {SCHEMA_PATH.relative_to(ROOT)}:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print(f"reason-code registry check passed: {len(codes)} entries valid against the v1 schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
