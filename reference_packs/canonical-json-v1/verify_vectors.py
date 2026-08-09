#!/usr/bin/env python3
"""Independent verifier for the HELM canonical JSON reference pack.

Python standard library only. This file is a complete, self-contained second
implementation of protocols/specs/rfc/canonical-json-v1.md: it does NOT call
json.dumps to canonicalize, so passing these vectors is evidence that the rule
is reproducible from the specification rather than from CPython's encoder.

quantum_posture: this verifier canonicalizes bytes and computes SHA-256
digests; it performs no signing and selects no classical, hybrid, or
post-quantum profile.
"""

import hashlib
import json
import sys
from pathlib import Path

MAX_SAFE_INTEGER = 9007199254740991

ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


class VectorError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class RawNumber:
    """A JSON number retained as its source literal.

    HELM canonical JSON emits the literal verbatim (see Section 4 of the
    specification). Parsing into a Python int or float and re-rendering would
    silently apply a different number rule.
    """

    __slots__ = ("literal",)

    def __init__(self, literal):
        self.literal = literal


def _reject_constant(name):
    raise VectorError("canonicalization_error", f"{name} is not valid JSON")


def parse_json(text):
    """Parse a JSON text, preserving number literals exactly."""
    return json.loads(
        text,
        parse_int=RawNumber,
        parse_float=RawNumber,
        parse_constant=_reject_constant,
    )


def escape_string(value):
    """RFC 8785 Section 3.2.2.2: escape only U+0000..U+001F, '"' and '\\'."""
    out = ['"']
    for char in value:
        replacement = ESCAPES.get(char)
        if replacement is not None:
            out.append(replacement)
        elif ord(char) < 0x20:
            out.append("\\u%04x" % ord(char))
        else:
            out.append(char)
    out.append('"')
    return "".join(out)


def utf16_sort_key(key):
    """RFC 8785 Section 3.2.3: compare property names as UTF-16 code units.

    Encoding to big-endian UTF-16 and comparing the resulting bytes is
    equivalent to comparing the code-unit sequences as unsigned integers.
    Python's native str comparison is code point order, which places a
    supplementary-plane key AFTER U+E000..U+FFFF instead of before it.
    """
    return key.encode("utf-16-be")


def canonicalize(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, RawNumber):
        return value.literal
    if isinstance(value, str):
        return escape_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(item) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value, key=utf16_sort_key):
            if not isinstance(key, str):
                raise VectorError("canonicalization_error", "object keys must be strings")
            parts.append(escape_string(key) + ":" + canonicalize(value[key]))
        return "{" + ",".join(parts) + "}"
    raise VectorError("canonicalization_error", f"unsupported JSON type {type(value)!r}")


def is_interoperable_literal(literal):
    """Section 5: the subset on which HELM and strict RFC 8785 agree."""
    if not literal or any(char in literal for char in ".eE"):
        return False
    body = literal[1:] if literal[0] == "-" else literal
    if literal[0] == "-" and body == "0":
        return False
    if not body or not body.isdigit():
        return False
    if len(body) > 1 and body[0] == "0":
        return False
    return abs(int(literal)) <= MAX_SAFE_INTEGER


def check_interoperable(value, path="$"):
    if isinstance(value, RawNumber):
        if not is_interoperable_literal(value.literal):
            raise VectorError(
                "non_interoperable_number", f"{path} is {value.literal!r}"
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            check_interoperable(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key in sorted(value, key=utf16_sort_key):
            check_interoperable(value[key], f"{path}.{key}")


def main():
    root = Path(__file__).resolve().parent
    document = json.loads((root / "vectors.json").read_text(encoding="utf-8"))
    failures = []

    for vector in document["vectors"]:
        identifier = vector["id"]
        parsed = parse_json(vector["input"])

        produced = canonicalize(parsed)
        if produced != vector["canonical"]:
            failures.append(
                f"{identifier}: canonical bytes differ\n  got:  {produced!r}\n  want: {vector['canonical']!r}"
            )
            continue

        digest = hashlib.sha256(produced.encode("utf-8")).hexdigest()
        if digest != vector["sha256"]:
            failures.append(f"{identifier}: sha256 {digest} != {vector['sha256']}")
            continue

        try:
            check_interoperable(parsed)
            interoperable = True
        except VectorError:
            interoperable = False
        if interoperable != vector["interoperable"]:
            failures.append(
                f"{identifier}: interoperable={interoperable}, vector says {vector['interoperable']}"
            )
            continue

        # Every vector outside the subset MUST publish what a strict RFC 8785
        # implementation produces instead, so the deviation is never silent.
        if not vector["interoperable"] and "rfc8785_canonical" not in vector:
            failures.append(f"{identifier}: deviation vector must state rfc8785_canonical")

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"{len(failures)} of {len(document['vectors'])} vectors failed", file=sys.stderr)
        return 1

    print(f"canonical-json-v1: {len(document['vectors'])} vectors verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
