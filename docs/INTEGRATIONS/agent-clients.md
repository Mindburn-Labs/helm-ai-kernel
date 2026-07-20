---
title: Agent Clients
last_reviewed: 2026-07-14
---

# Agent Clients

Start with `setup`. It shows the supported clients without writing config.

```bash
helm-ai-kernel setup
helm-ai-kernel setup --json
```

## Direct Setup

| Client | Command |
| --- | --- |
| Claude Code | `helm-ai-kernel setup claude-code --yes` |
| Codex | `helm-ai-kernel setup codex --yes` |

Preview writes first:

```bash
helm-ai-kernel setup claude-code --dry-run --json
helm-ai-kernel setup codex --dry-run --json
```

## Config Print

| Client | Command |
| --- | --- |
| Cursor | `helm-ai-kernel setup --client cursor --print-config` |
| Windsurf | `helm-ai-kernel setup --client windsurf --print-config` |
| VS Code | `helm-ai-kernel setup --client vscode --print-config` |

Claude Desktop uses a bundle:

```bash
helm-ai-kernel mcp pack --client claude-desktop --out helm-ai-kernel.mcpb
```

## What HELM Does

```text
agent/tool requests action
-> HELM evaluates before dispatch
-> ALLOW: action runs
-> DENY: action is blocked
-> ESCALATE: action is blocked and a receipt is written
```

Setup writes local config and draft policy files only when `--yes` is present.
It does not approve detected tools.

## Native-Client Limits

| Client path | Local evidence | Not established by setup |
| --- | --- | --- |
| Codex project scope | Exact owned config, signed lifecycle receipt, recovery journal, and Kernel-only synthetic denial | That a real Codex session loaded the config or governed any action outside the configured hook classes and routed MCP calls |
| Claude Code | Direct CLI used to request MCP registration plus selected PreToolUse hook configuration | Readback of CLI-owned MCP serialization, Codex-style project lifecycle/recovery, or a real Claude Code session result |

The Codex project lifecycle is intentionally isolated by workspace under the
selected data directory. If it is interrupted, use `setup recover codex --scope
project --yes`; migrate old unscoped state with `setup migrate codex --scope
project --yes`. See the [Native Client Integration
Boundary](native-client-boundary.md) for what that setup can and cannot prove.
