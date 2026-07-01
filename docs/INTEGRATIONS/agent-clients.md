---
title: Agent Clients
last_reviewed: 2026-07-01
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
