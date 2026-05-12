#!/usr/bin/env python3
"""Parse and optionally compile repository JSON Schema files."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOTS = (
    ROOT / "schemas",
    ROOT / "protocols" / "json-schemas",
    ROOT / "protocols" / "specs",
)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path.relative_to(ROOT)}:{exc.lineno}:{exc.colno}: {exc.msg}") from exc


def optional_jsonschema_check(path: Path, payload: Any) -> str | None:
    try:
        import jsonschema.validators  # type: ignore[import-not-found]
    except Exception:
        return None

    try:
        validator = jsonschema.validators.validator_for(payload)
        validator.check_schema(payload)
    except Exception as exc:
        raise ValueError(f"{path.relative_to(ROOT)} failed jsonschema compilation: {exc}") from exc
    return "jsonschema"


def main() -> int:
    failures: list[str] = []
    schema_count = 0
    compiled_count = 0
    ids: dict[str, Path] = {}

    for root in SCHEMA_ROOTS:
        if not root.exists():
            failures.append(f"missing schema root: {root.relative_to(ROOT)}")
            continue
        for path in sorted(root.rglob("*.json")):
            schema_count += 1
            try:
                payload = load_json(path)
                if not isinstance(payload, dict):
                    raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
                schema_id = payload.get("$id")
                if isinstance(schema_id, str):
                    if schema_id in ids:
                        failures.append(
                            f"duplicate $id {schema_id!r}: {ids[schema_id].relative_to(ROOT)} and {path.relative_to(ROOT)}"
                        )
                    ids[schema_id] = path
                if "$schema" in payload or "$defs" in payload or "properties" in payload:
                    if optional_jsonschema_check(path, payload):
                        compiled_count += 1
            except ValueError as exc:
                failures.append(str(exc))

    if failures:
        print("JSON schema check failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1

    if compiled_count == 0:
        print("jsonschema package unavailable; completed JSON parse and structural checks only.")
    print(f"JSON schema check passed: {schema_count} files parsed, {compiled_count} schemas compiled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
