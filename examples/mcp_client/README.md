# MCP Client Example

Shows HELM's MCP (Model Context Protocol) gateway integration.

## Prerequisites

- HELM running at `http://localhost:8080` (`docker compose up -d`)
- `curl` and `jq`

## Run

```bash
bash main.sh
```

## Expected Output

```
=== MCP Capabilities ===
"file_read"
"file_write"

=== Execute Governed Tool ===
{
  "result": "...",
  "receipt_id": "rec_...",
  "reason_code": "ALLOW"
}

=== Denied Tool Call ===
{
  "error": {
    "message": "Tool not found: unknown_tool",
    "reason_code": "DENY_TOOL_NOT_FOUND"
  }
}
```
