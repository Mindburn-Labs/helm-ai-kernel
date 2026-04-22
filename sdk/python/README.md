# HELM SDK — Python

Typed Python client for the retained HELM kernel API.

## Install

```bash
pip install helm-sdk
```

## Local Development

```bash
pip install '.[dev]'
pytest -v --tb=short
```

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
