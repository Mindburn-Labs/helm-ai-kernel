# helm-anthropic

HELM governance adapter for [Anthropic Claude SDK](https://docs.anthropic.com).

## What it does

Governs Anthropic Claude tool_use calls through HELM:

1. Every tool_use content block is evaluated against HELM policy before execution
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_anthropic import HelmAnthropicGovernor

governor = HelmAnthropicGovernor(helm_url="http://localhost:8080")
response = anthropic_client.messages.create(model="claude-sonnet-4-20250514", ...)
approved = governor.govern_message_response(response)
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
