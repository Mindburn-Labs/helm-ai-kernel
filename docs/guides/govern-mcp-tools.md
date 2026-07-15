---
title: Govern MCP Tools
last_reviewed: 2026-07-15
---

# Govern MCP Tools

Wrap an MCP server, require schema pins, and inspect the receipts for allowed,
denied, or escalated tool calls.

## 1. Start HELM

```bash
helm-ai-kernel serve --policy ./release.high_risk.v3.toml
```

## 2. Wrap The Server

```bash
helm-ai-kernel mcp wrap \
  --server-id shell-mcp-server \
  --upstream-command "npx -y shell-mcp-server" \
  --require-pinned-schema=true \
  --json
```

## 3. Configure The Client

```bash
helm-ai-kernel mcp print-config --client codex
```

Supported print targets include `windsurf`, `codex`, `vscode`, and `cursor`.
Claude Code uses:

```bash
helm-ai-kernel mcp install --client claude-code
```

These commands describe or request only a configured MCP route. Printing a
Codex command or asking a client CLI to install a server does not prove that a
native client loaded the configuration, and it does not cover direct upstream
calls or unconfigured client actions. Local setup evidence remains
`client_load_observed=false` until a sterile client session visibly loads the
configured server. For Codex project setup, inspect local lifecycle changes
before writing them:

```bash
helm-ai-kernel setup codex --scope project --dry-run --json
```

## 4. Verify The Local MCP Boundary

```bash
./scripts/launch/demo-mcp.sh
```

This demo starts a local HELM boundary and fixture server; it verifies that
local MCP authorization paths fail closed. It does not start a native client or
show that Codex or Claude Code loaded client configuration. That claim requires
a sterile client session which observes the configured server and exercises the
specific routed MCP call (and any configured hook class) under review. See the
[native client integration boundary](../INTEGRATIONS/native-client-boundary.md).

## 5. Inspect Receipts

```bash
helm-ai-kernel receipts tail --agent mcp-demo-agent --server http://127.0.0.1:7714
```

These receipts cover only calls that reached the configured HELM server.

## Source Truth

- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_runtime.go`
- `scripts/launch/demo-mcp.sh`
- `examples/launch/policies/shell_mcp_server_boundary.json`
- `docs/INTEGRATIONS/mcp.md`
