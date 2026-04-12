# helm-haystack

HELM governance adapter for [Deepset Haystack](https://haystack.deepset.ai).

## What it does

Governs Haystack pipeline components and tool invocations through HELM:

1. Every component.run() call is evaluated against HELM policy before execution
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_haystack import HelmHaystackGovernor

governor = HelmHaystackGovernor(helm_url="http://localhost:8080")
governed = governor.govern_component(my_retriever)
result = governed.run(query="what is HELM?")
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
