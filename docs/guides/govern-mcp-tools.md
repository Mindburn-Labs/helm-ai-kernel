---
title: Govern MCP Tools
last_reviewed: 2026-06-29
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

## 4. Verify Behavior

```bash
./scripts/launch/demo-mcp.sh
```

## 5. Inspect Receipts

```bash
helm-ai-kernel receipts tail --agent mcp-demo-agent --server http://127.0.0.1:7714
```

## Source Truth

- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_runtime.go`
- `scripts/launch/demo-mcp.sh`
- `examples/launch/policies/shell_mcp_server_boundary.json`
- `docs/INTEGRATIONS/mcp.md`
