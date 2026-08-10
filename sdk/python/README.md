# HELM SDK - Python

Typed Python client for the retained HELM kernel API.

## Local Install

```bash
cd sdk/python
python -m pip install .
```

Package metadata identifies source target `0.8.4`; this README does not claim
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
from helm_sdk import EvaluateRequest, HelmClient

client = HelmClient(base_url="http://127.0.0.1:7714")
decision = client.evaluate_decision_v5(EvaluateRequest(
    tool="read-ticket",
    effect_level="ticket:123",
    session_id="example-session",
))
print(decision.verdict)  # ALLOW or DENY
```

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

## Source target

The SDK requires canonical typed evaluation and returns receipt-bearing V5
responses. Verify registry evidence before using a pinned package coordinate.
