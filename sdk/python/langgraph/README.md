# helm-langgraph

HELM governance adapter for [LangGraph](https://langchain-ai.github.io/langgraph/).

## What it does

Governs LangGraph node execution through HELM:

1. Every graph node execution is evaluated against HELM policy before running
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_langgraph import HelmLangGraphGovernor

governor = HelmLangGraphGovernor(helm_url="http://localhost:8080")
governed_search = governor.govern_node("search", search_node_fn)
graph.add_node("search", governed_search)
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
