# helm-semantic-kernel

HELM governance adapter for [Microsoft Semantic Kernel](https://learn.microsoft.com/en-us/semantic-kernel/).

## What it does

Governs Semantic Kernel function and plugin calls through HELM:

1. Every kernel function invocation is evaluated against HELM policy before execution
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_semantic_kernel import HelmSemanticKernelGovernor

governor = HelmSemanticKernelGovernor(helm_url="http://localhost:8080")
governed_fn = governor.govern_function("search", "web_search", search_fn)
# Or govern FunctionCallContent objects
governor.govern_function_call_content(function_call)
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
