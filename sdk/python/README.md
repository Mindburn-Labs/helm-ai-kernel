# HELM SDK - Python

Typed Python client for the retained HELM kernel API.

## Local Install

```bash
cd sdk/python
python -m pip install .
```

Package metadata declares version `0.7.2` in `pyproject.toml`; this README does
not claim that a registry package has been published.

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

from helm_sdk import HelmClient

client = HelmClient(
    base_url=os.getenv("HELM_BASE_URL", "http://127.0.0.1:7714"),
    api_key=os.environ["HELM_API_KEY"],
    tenant_id=os.environ["HELM_TENANT_ID"],
    principal_id=os.environ["HELM_PRINCIPAL_ID"],
    # Required only when scoped emergency-stop fencing is enabled.
    workspace_id=os.getenv("HELM_WORKSPACE_ID"),
)
decision = client.evaluate_decision({
    "principal": "example-agent",
    "action": "read-ticket",
    "resource": "ticket:123",
})
print(decision["verdict"])  # ALLOW, DENY, or ESCALATE
```

`/api/v1/evaluate` requires `HELM_API_KEY`, `HELM_TENANT_ID`, and
`HELM_PRINCIPAL_ID`. Set `HELM_WORKSPACE_ID` only when scoped emergency-stop
fencing is enabled. Other routes keep these client options optional.

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

## Release Notes

`0.7.2` is the release-hardening patch with the retained OpenAPI client surface and local test coverage.
