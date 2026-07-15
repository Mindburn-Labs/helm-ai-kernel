---
title: Claude Code Integration
last_reviewed: 2026-07-15
---

# Claude Code Integration

Use HELM to register local Claude Code MCP configuration, write a local
PreToolUse hook configuration, and create draft policy artifacts.

## Quick Setup

```bash
helm-ai-kernel setup claude-code --yes
```

Check what was installed:

```bash
helm-ai-kernel setup status claude-code
```

Undo the local integration:

```bash
helm-ai-kernel setup remove claude-code --yes
```

## Inspect Before Writing

```bash
helm-ai-kernel setup claude-code --dry-run --json
```

The JSON summary includes the binary path, client config path, hook config path,
data dir, Kernel URL, draft policy path, and uninstall command.

**Evidence boundary:** setup artifact proof is not client-runtime proof. The
source tests cover target CLI/config and hook artifacts; they do not prove a
particular installed Claude Code version loaded them, emitted a hook event, or
routed a live tool call through HELM.

## Verify A Denial

Denied hook decisions write signed receipts under:

```text
~/.helm-ai-kernel/receipts/hooks/
```

Verify one:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

This verifies an existing receipt; it is not evidence that Claude Code emitted
it.

## MCP Configuration

For lower-level MCP configuration, install the Claude Code MCP server:

```bash
helm-ai-kernel mcp install --client claude-code
```

Claude Desktop bundle output is separate:

```bash
helm-ai-kernel mcp pack --client claude-desktop --out helm-ai-kernel.mcpb
```

## Implementation

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
