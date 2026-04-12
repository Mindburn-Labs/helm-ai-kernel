# HELM x MCP Trust (Python)

HELM governance layer for MCP tool calls at the protocol level.

## Install

```bash
pip install helm
```

## Quick Integration

```python
from helm_mcp_trust import MCPTrustProxy

proxy = MCPTrustProxy(helm_url="http://localhost:8080")

# Verify a tool call before execution
result = proxy.verify_tool_call("file_write", {"path": "/tmp/out.txt"})
if result.allowed:
    # proceed with tool execution
    pass

# Filter tool list by policy
available_tools = [
    {"name": "file_read", "description": "Read a file"},
    {"name": "file_write", "description": "Write a file"},
    {"name": "shell_exec", "description": "Execute shell command"},
]
allowed = proxy.get_allowed_tools(available_tools)

# Export evidence
proxy.export_evidence_pack("evidence.tar")
```

## Configuration

| Parameter          | Default                | Description                     |
| ------------------ | ---------------------- | ------------------------------- |
| `helm_url`         | `http://localhost:8080` | HELM kernel URL                |
| `principal`        | `mcp-client`           | Default caller identity         |
| `fail_closed`      | `True`                 | Deny on HELM errors             |
| `collect_receipts` | `True`                 | Keep receipt chain              |
| `metadata`         | `None`                 | Global metadata for receipts    |

## Tests

```bash
cd sdk/python && pytest mcp_trust/ -v
```

## License

Apache-2.0
