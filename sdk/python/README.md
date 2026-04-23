# HELM SDK — Python

Typed Python client for the retained HELM kernel API.

## Install

```bash
pip install helm-sdk
```

Published package version is `0.4.0` and is declared in `pyproject.toml`.

## Local Development

```bash
pip install '.[dev]'
pytest -v --tb=short
```

## Generated Sources

`helm_sdk/types_gen.py` is generated from `api/openapi/helm.openapi.yaml`. The Python SDK does not currently ship generated protobuf bindings.

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

## Release Notes

`0.4.0` is the cleaned OSS kernel baseline with the retained OpenAPI client surface and local test coverage.
