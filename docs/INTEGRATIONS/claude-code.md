---
title: Claude Code Integration
last_reviewed: 2026-06-29
---

# Claude Code Integration

Use HELM with Claude Code when you want local PreToolUse decisions and signed
receipts for selected high-risk tool effects.

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

## MCP Configuration

For lower-level MCP configuration, print the Claude Code config:

```bash
helm-ai-kernel mcp print-config --client claude-code
```

Claude Desktop bundle output is separate:

```bash
helm-ai-kernel mcp pack --client claude-desktop --out helm-ai-kernel.mcpb
```

## Source Truth

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
