# helm-smolagents

HELM governance adapter for [HuggingFace Smolagents](https://huggingface.co/docs/smolagents).

## What it does

Governs Smolagents tool execution through HELM:

1. Every tool call is evaluated against HELM policy before execution
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_smolagents import HelmSmolagentsGovernor

governor = HelmSmolagentsGovernor(helm_url="http://localhost:8080")
governed_tools = governor.govern_tools(my_tools)
agent = CodeAgent(tools=governed_tools, model=model)
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
