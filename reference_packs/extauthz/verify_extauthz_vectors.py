#!/usr/bin/env python3
import hashlib
import json
import re
from pathlib import Path

VALID_VERDICT_HASH = "0" * 64
VALID_VERDICT_SIGNATURE = "0" * 128


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def load_json(path):
    return json.loads(path.read_text())


def make_wire_response(response):
    """Canonical response vectors are signable payloads, so signature fields are blank.

    Wire-schema validation needs syntactically valid signature material; cryptographic
    verification is covered by Go tests in core/pkg/boundary/extauthz.
    """
    wire = dict(response)
    if wire.get("kernel_verdict_hash", "") == "":
        wire["kernel_verdict_hash"] = VALID_VERDICT_HASH
    if wire.get("kernel_verdict_signature", "") == "":
        wire["kernel_verdict_signature"] = VALID_VERDICT_SIGNATURE
    return wire


def validate_with_jsonschema(schema, documents, invalid_documents):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except Exception:
        return False

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    for name, document in documents:
        errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
        if errors:
            details = "; ".join(error.message for error in errors[:3])
            raise SystemExit(f"{name}: schema validation failed: {details}")
    for name, document in invalid_documents:
        if validator.is_valid(document):
            raise SystemExit(f"{name}: invalid schema case unexpectedly passed")
    return True


def validate_with_fallback(schema, documents, invalid_documents):
    for name, document in documents:
        errors = validate_document_fallback(schema, document)
        if errors:
            raise SystemExit(f"{name}: fallback schema validation failed: {'; '.join(errors[:3])}")
    for name, document in invalid_documents:
        if not validate_document_fallback(schema, document):
            raise SystemExit(f"{name}: invalid fallback schema case unexpectedly passed")


def validate_document_fallback(schema, document):
    errors = []
    if set(document) - set(schema["properties"]):
        errors.append("top-level additional properties")
    for field in schema["required"]:
        if field not in document:
            errors.append(f"missing {field}")
    if document.get("schema_version") != "extauthz.v1":
        errors.append("bad schema_version")
    if document.get("contract_version") != "2026-06-01":
        errors.append("bad contract_version")
    errors.extend(validate_object_fallback(schema["$defs"]["request"], document.get("request", {}), "request"))
    errors.extend(validate_object_fallback(schema["$defs"]["response"], document.get("response", {}), "response"))
    return errors


def validate_object_fallback(schema, value, label):
    errors = []
    properties = schema["properties"]
    if not isinstance(value, dict):
        return [f"{label} is not an object"]
    extra = set(value) - set(properties)
    if extra:
        errors.append(f"{label} additional properties: {sorted(extra)}")
    for field in schema["required"]:
        if field not in value:
            errors.append(f"{label} missing {field}")
    for field, spec in properties.items():
        if field not in value:
            continue
        errors.extend(validate_value_fallback(spec, value[field], f"{label}.{field}"))

    if label == "response":
        verdict = value.get("verdict")
        permit_fields = {
            "effect_permit_ref",
            "permit_nonce",
            "permit_expiry",
            "proof_session_ref",
            "evidence_reservation_ref",
        }
        if verdict == "ALLOW":
            for field in permit_fields | {"proof_obligation"}:
                if not value.get(field):
                    errors.append(f"response missing allow {field}")
            if value.get("replay_hint") != "single_use_permit":
                errors.append("response allow replay_hint must be single_use_permit")
            if "denial_receipt_ref" in value or "escalation_ref" in value:
                errors.append("response allow carries denial or escalation material")
        if verdict in {"DENY", "ESCALATE"}:
            carried = permit_fields & set(value)
            if carried:
                errors.append(f"response non-allow carries permit material: {sorted(carried)}")
    return errors


def validate_value_fallback(spec, value, label):
    errors = []
    if "$ref" in spec:
        ref = spec["$ref"].removeprefix("#/$defs/")
        if ref == "non_empty":
            if not isinstance(value, str) or value == "":
                errors.append(f"{label} must be non-empty string")
        elif ref == "hash":
            if not isinstance(value, str) or not re.match(r"^sha256:[a-f0-9]{64}$", value):
                errors.append(f"{label} must be hash")
        return errors
    if "const" in spec and value != spec["const"]:
        errors.append(f"{label} must equal {spec['const']}")
    if "enum" in spec and value not in spec["enum"]:
        errors.append(f"{label} must be one of {spec['enum']}")
    if spec.get("type") == "string" and not isinstance(value, str):
        errors.append(f"{label} must be string")
    if spec.get("type") == "integer":
        if not isinstance(value, int):
            errors.append(f"{label} must be integer")
        elif "minimum" in spec and value < spec["minimum"]:
            errors.append(f"{label} below minimum")
    if "pattern" in spec and (not isinstance(value, str) or not re.match(spec["pattern"], value)):
        errors.append(f"{label} does not match pattern")
    return errors


def schema_documents(root):
    request = load_json(root / "allow_request.c14n.json")
    responses = {
        "allow": load_json(root / "allow_response.c14n.json"),
        "deny": load_json(root / "deny_response.c14n.json"),
        "escalate": load_json(root / "escalate_response.c14n.json"),
    }
    valid = [
        (
            f"{name}_wire_document",
            {
                "schema_version": "extauthz.v1",
                "contract_version": "2026-06-01",
                "request": request,
                "response": make_wire_response(response),
            },
        )
        for name, response in responses.items()
    ]

    invalid = []
    bad_allow = make_wire_response(responses["allow"])
    bad_allow["denial_receipt_ref"] = "denial:forbidden"
    invalid.append(("allow_with_denial_material", wrapper(request, bad_allow)))

    bad_deny = make_wire_response(responses["deny"])
    bad_deny["effect_permit_ref"] = "permit:forbidden"
    invalid.append(("deny_with_permit_material", wrapper(request, bad_deny)))

    bad_final_proof = make_wire_response(responses["allow"])
    bad_final_proof["effect_receipt_ref"] = "receipt:forbidden"
    invalid.append(("pre_dispatch_with_final_effect_receipt", wrapper(request, bad_final_proof)))

    bad_protocol_request = dict(request)
    bad_protocol_request["protocol"] = "ftp"
    invalid.append(("unsupported_protocol_request", wrapper(bad_protocol_request, make_wire_response(responses["allow"]))))

    symbolic_hash_request = dict(request)
    symbolic_hash_response = make_wire_response(responses["allow"])
    symbolic_hash_request["request_body_hash"] = "sha256:request"
    symbolic_hash_response["request_body_hash"] = symbolic_hash_request["request_body_hash"]
    invalid.append(("symbolic_request_hash", wrapper(symbolic_hash_request, symbolic_hash_response)))

    blank_signature = dict(responses["allow"])
    invalid.append(("blank_wire_signature", wrapper(request, blank_signature)))
    return valid, invalid


def wrapper(request, response):
    return {
        "schema_version": "extauthz.v1",
        "contract_version": "2026-06-01",
        "request": request,
        "response": response,
    }


def main():
    root = Path(__file__).resolve().parent
    repo = root.parent.parent
    schema = load_json(repo / "protocols/json-schemas/boundary/extauthz.v1.schema.json")
    index = load_json(root / "vectors.json")
    for vector in index["vectors"]:
        source = load_json(root / vector["input"])
        expected = (root / vector["canonical"]).read_text().removesuffix("\n")
        actual = canonical_json(source)
        if actual != expected:
            raise SystemExit(f"{vector['id']}: canonical mismatch\nactual={actual}\nexpected={expected}")
        digest = hashlib.sha256(actual.encode("utf-8")).hexdigest()
        if digest != vector["sha256"]:
            raise SystemExit(f"{vector['id']}: hash mismatch {digest} != {vector['sha256']}")

    valid_documents, invalid_documents = schema_documents(root)
    used_jsonschema = validate_with_jsonschema(schema, valid_documents, invalid_documents)
    if not used_jsonschema:
        validate_with_fallback(schema, valid_documents, invalid_documents)
    validator_name = "jsonschema" if used_jsonschema else "fallback"
    print(f"verified {len(index['vectors'])} extauthz vectors and {len(valid_documents) + len(invalid_documents)} schema cases with {validator_name}")


if __name__ == "__main__":
    main()
