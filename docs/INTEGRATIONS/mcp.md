---
title: mcp
---

# Integration: Model Context Protocol (MCP)

HELM provides an MCP gateway that governs tool execution via the MCP protocol.
The OSS runtime exposes two surfaces:

- `/mcp` for modern streamable HTTP / JSON-RPC clients with protocol negotiation
- `/mcp/v1/*` as a legacy HTTP compatibility layer for scripts and smoke tests

Protocol version: **2025-11-25** (also supports 2025-06-18 and 2025-03-26).

## Claude Desktop Integration

### Option 1: MCPB Bundle (recommended)

Build and install the .mcpb bundle:

```bash
make mcp-pack          # produces dist/helm.mcpb
```

Then double-click `dist/helm.mcpb` or drag it into Claude Desktop.

The bundle contains:
- `manifest.json` — full capability manifest with tool definitions, protocol version, and governance metadata
- `claude_desktop_config.json` — drop-in config snippet
- `server/helm` — the HELM binary

### Option 2: Manual Configuration

Add the following to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "helm-governance": {
      "command": "/path/to/helm",
      "args": ["mcp", "serve", "--transport", "stdio"],
      "env": {}
    }
  }
}
```

Replace `/path/to/helm` with the absolute path to your built binary (`bin/helm`).

### Option 3: Remote HTTP

Start the server and point Claude Desktop at the remote URL:

```bash
helm mcp serve --transport http --port 9100
```

The MCP endpoint is `http://localhost:9100/mcp`.

## Claude Code Integration

```bash
make mcp-install       # generates helm-mcp-plugin/
claude plugin install ./helm-mcp-plugin
```

## Other Clients

```bash
helm mcp print-config --client windsurf   # Windsurf
helm mcp print-config --client cursor     # Cursor
helm mcp print-config --client vscode     # VS Code
helm mcp print-config --client codex      # Codex
```

## Modern MCP Endpoint

Initialize a remote MCP session:

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}' | jq .
```

List tools with negotiated protocol headers:

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq '.result.tools[] | {name, title, outputSchema, annotations}'
```

Call a governed tool:

```bash
curl -s -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"file_read","arguments":{"path":"/tmp/test.txt"}}}' | jq .
```

**Expected:** `result.content[]`, `result.structuredContent`, and `result.receipt_id` when the call is allowed.

## Legacy Capabilities

```bash
curl -s http://localhost:8080/mcp/v1/capabilities | jq '.tools[].name'
```

## Legacy Execute a Governed Tool

```bash
curl -s -X POST http://localhost:8080/mcp/v1/execute \
  -H 'Content-Type: application/json' \
  -d '{"method":"file_read","params":{"path":"/tmp/test.txt"}}' | jq .
```

**Expected:**
```json
{
  "result": "...",
  "receipt_id": "rec_...",
  "reason_code": "ALLOW"
}
```

## Denied Tool Call

```bash
curl -s -X POST http://localhost:8080/mcp/v1/execute \
  -H 'Content-Type: application/json' \
  -d '{"method":"unknown_tool","params":{}}' | jq .
```

**Expected:**
```json
{
  "error": {
    "message": "Tool not found: unknown_tool",
    "reason_code": "DENY_TOOL_NOT_FOUND"
  }
}
```

## OAuth Discovery for Remote HTTP

```bash
HELM_OAUTH_BEARER_TOKEN=testtoken helm mcp serve --transport http --port 9100 --auth oauth
curl -s http://localhost:9100/.well-known/oauth-protected-resource/mcp | jq .
```

The OSS runtime uses a local bearer-token gate for remote HTTP and publishes protected-resource metadata for clients that understand MCP OAuth discovery.

## What HELM Adds to MCP

- **Fail-closed governance** — all tool calls pass through the Guardian 6-gate pipeline (Freeze, Context, Identity, Egress, Threat, Delegation)
- **Schema PEP** — input and output validation on every tool call (JCS canonical hash)
- **Protocol negotiation** — supports `2025-11-25`, `2025-06-18`, and `2025-03-26`
- **Structured tool results** — `structuredContent` + text content for backwards compatibility
- **Receipts** — Ed25519-signed execution receipts with receipt IDs
- **ProofGraph** — append-only DAG of all tool executions
- **Rug-pull detection** — cryptographic fingerprinting detects tool definition mutations between sessions
- **Typosquat detection** — Levenshtein-based cross-server tool name similarity checks
- **Trust scoring** — behavioral trust scores (0-1000) for MCP tools based on schema stability, uptime, error rate
- **Delegation scoping** — per-session tool access control for delegated agents
- **Elicitation** — structured approval/input requests for ESCALATE verdicts

## Bundle Manifest

The project root `mcp-bundle.json` is the canonical description of the HELM MCP server capabilities. It is used by `helm mcp pack` to generate the `.mcpb` bundle and can be referenced by CI/CD tooling.

Full example: [examples/mcp_client/](../../examples/mcp_client/)
