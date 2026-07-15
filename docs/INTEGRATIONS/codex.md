---
title: Codex Integration
last_reviewed: 2026-07-15
---

# Codex Integration

Use HELM to register local Codex MCP configuration, write a local pre-tool hook
configuration, and create draft policy artifacts.

## Quick Setup

```bash
helm-ai-kernel setup codex --yes
```

Project scope:

```bash
helm-ai-kernel setup codex --scope project --yes
```

Check status:

```bash
helm-ai-kernel setup status codex
```

Remove the integration:

```bash
helm-ai-kernel setup remove codex --yes
```

## Inspect Before Writing

```bash
helm-ai-kernel setup codex --dry-run --json
```

The dry run writes nothing and returns the target config paths, data dir, Kernel
URL, draft policy path, and uninstall command.

**Evidence boundary:** setup artifact proof is not client-runtime proof. The
source tests cover target CLI/config and hook artifacts; they do not prove a
particular installed Codex version loaded them, emitted a hook event, or routed
a live tool call through HELM.

## Manual MCP Setup

Print Codex MCP configuration:

```bash
helm-ai-kernel mcp print-config --client codex
```

The CLI also prints a `codex mcp add ...` command for stdio transport where the
local Codex CLI supports it.

## Verify A Denial

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

Tampered receipts return a non-zero exit and fail signature verification.
This verifies an existing receipt; it is not evidence that Codex emitted it.

## Source Truth

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/setup_cmd_test.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
