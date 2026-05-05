# HELM SDK - Python

Typed Python client for the retained HELM kernel API.

## Install

```bash
pip install helm-sdk
```

Package metadata declares version `0.4.0` in `pyproject.toml`.

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
from helm_sdk import HelmClient, HelmApiError, ChatCompletionRequest, ChatMessage

client = HelmClient(base_url="http://localhost:8080")

try:
    result = client.chat_completions(
        ChatCompletionRequest(
            model="gpt-4",
            messages=[ChatMessage(role="user", content="hello")],
        )
    )
    print(result.choices[0].message.content)
except HelmApiError as err:
    print(err.reason_code)
```

## Execution Boundary Methods

The client includes helpers for the May 2026 execution-boundary surfaces:
evidence envelope manifests, boundary records and checkpoints, conformance
vectors, MCP quarantine and authorization profiles, sandbox profiles and
grants, authz snapshots, approvals, budgets, telemetry export, and coexistence
capabilities.

External evidence envelopes remain compatibility wrappers; HELM-native
EvidencePack roots stay authoritative.

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and local test coverage.
