# helm-mistral

HELM governance adapter for [Mistral AI](https://docs.mistral.ai).

## What it does

Governs Mistral AI SDK tool/function calls through HELM:

1. Every tool_call in chat completions is evaluated against HELM policy before execution
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_mistral import HelmMistralGovernor

governor = HelmMistralGovernor(helm_url="http://localhost:8080")
governor.govern_tool("web_search", {"query": "latest news"})
# Or govern an entire chat response
approved = governor.govern_chat_response(mistral_response)
```

## Configuration

| Parameter          | Default                 | Description          |
| ------------------ | ----------------------- | -------------------- |
| `helm_url`         | `http://localhost:8080` | HELM kernel URL      |
| `api_key`          | `None`                  | HELM API key         |
| `fail_closed`      | `True`                  | Deny on HELM errors  |
| `collect_receipts` | `True`                  | Keep receipt chain   |
| `timeout`          | `30.0`                  | HTTP timeout seconds |

## License

Apache-2.0
