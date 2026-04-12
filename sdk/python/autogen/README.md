# helm-autogen

HELM governance adapter for [Microsoft AutoGen](https://microsoft.github.io/autogen/).

## What it does

Governs AutoGen multi-agent function and tool calls through HELM:

1. Every function_call and tool invocation is evaluated against HELM policy before execution
2. Denied calls raise `HelmToolDenyError` (fail-closed by default)
3. Receipts with SHA-256 hashes are collected for every approved execution

## Quick start

```python
from helm_autogen import HelmAutoGenGovernor

governor = HelmAutoGenGovernor(helm_url="http://localhost:8080")
governed_fn = governor.govern_tool("code_exec", execute_code, agent_name="assistant")
# Or govern messages with function_call fields
governor.govern_message(message, agent_name="assistant")
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
