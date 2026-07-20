---
title: Claude Code Integration
last_reviewed: 2026-07-14
---

# Claude Code Integration

Use HELM with Claude Code when you want local PreToolUse decisions and signed
receipts for selected high-risk tool effects. This is a selected-hook and MCP
configuration path, not a claim of full Claude Code control.

## Quick Setup

```bash
helm-ai-kernel setup claude-code --yes
```

Setup resolves a direct `claude` executable. If PATH resolves through a mise
shim, it refuses the install rather than trusting the shim. Supply the direct
executable path when needed:

```bash
CLAUDE_CODE_BIN=/absolute/path/to/claude helm-ai-kernel setup claude-code --yes
```

`CLAUDE_CODE_BIN` must be an executable path, not a bare command name.

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

The JSON summary includes the Kernel binary path, client config path, hook
config path, data dir, Kernel URL, draft policy path, and uninstall command.

The summary identifies HELM's planned paths and local hook state. Claude Code
owns MCP config serialization, so HELM does not read back that registration or
claim a live Claude Code session loaded it. It also does not establish Codex-style
project lifecycle or recovery semantics. See the [native client integration
boundary](native-client-boundary.md) for the public boundary and review rules.

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
- `docs/INTEGRATIONS/native-client-boundary.md`
