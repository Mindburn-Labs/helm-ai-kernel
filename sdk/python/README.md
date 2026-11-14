<!-- quantum_posture: offline receipt.v5 verification is classical Ed25519 only; no post-quantum protection is claimed. -->

# HELM SDK - Python

Typed Python client for the retained HELM kernel API.

## Local Install

```bash
cd sdk/python
python -m pip install .
```

Package metadata identifies source target `0.12.0`; this README does not claim
that a registry package has been published.

## Local Development

```bash
pip install '.[dev]'
pytest -v --tb=short
```

## Generated Sources

`helm_sdk/types_gen.py` is generated from `api/openapi/helm.openapi.yaml`.
Generated protobuf modules live under `helm_sdk/generated/` when codegen has
been run.

## Usage

```python
import os

from helm_sdk import EvaluateRequest, HelmClient

client = HelmClient(
    base_url="http://127.0.0.1:7714",
    api_key=os.environ["HELM_ADMIN_API_KEY"],
    tenant_id="tenant-a",
    principal_id="operator-a",
)
decision = client.evaluate_decision_v5(EvaluateRequest(
    tool="read-ticket",
    effect_level="ticket:123",
    session_id="example-session",
))
print(decision.verdict)  # ALLOW, DENY or ESCALATE
```

`/api/v1/evaluate` needs the API key and the tenant and principal the server is
configured for; without them the call raises `HelmApiError` with status 401.

Run the first-class local example with `make sdk-examples-smoke` or directly
from `examples/python_sdk/`.

## Execution Boundary Methods

The client includes helpers for the May 2026 execution-boundary surfaces:
evidence envelope manifests, boundary records and checkpoints, conformance
vectors, MCP quarantine and authorization profiles, sandbox profiles and
grants, authz snapshots, approvals, budgets, telemetry export, and coexistence
capabilities.

External evidence envelopes remain compatibility wrappers; HELM-native
EvidencePack roots stay authoritative.

## Offline receipt verification

```python
from helm_sdk import verify_receipt

raw = helm.get_receipt_json(receipt_id)
result = verify_receipt(raw, trusted_public_key_hex)
if not result.valid:
    raise ValueError(result.detail)
print(result.verdict, result.signed)
```

The SDK requires Python 3.9.2 or newer and uses `cryptography` 50.0.2 or newer
within major version 50 for Ed25519 verification.

The verifier checks the classical Ed25519 signature of one `receipt.v5`
envelope using public keys supplied by the caller. It makes no network request.
Pass the original JSON bytes: decoding and re-encoding can hide duplicate members
and change number spellings. Invalid UTF-8, duplicate names, typed member-name
case aliases, nesting beyond 64 containers and non-interoperable clock values
are refused. Legacy, hybrid and post-quantum signatures are not supported.

Only the thirteen members returned in the signed-field map are authenticated.
`key_id`, timestamps, tool names and other metadata are unsigned claims; their
schemas are not validated by this function. A successful result does not establish
chain closure, permits or gateway bindings. Use `receipt_verify` for those
additional checks. Neither verifier attests that an external effect actually
executed. Obtain trusted public keys independently of the
receipt; an embedded key or a key fetched from its producer is not a trust root.

## Source target

The SDK requires canonical typed evaluation and returns receipt-bearing V5
responses. Verify registry evidence before using a pinned package coordinate.
