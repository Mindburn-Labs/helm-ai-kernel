---
title: Agent Clients
last_reviewed: 2026-07-15
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

## Setup Evidence Boundary

Setup writes or registers local MCP configuration, writes local hook
configuration, and creates draft policy artifacts only when `--yes` is present.
It does not approve detected tools.

**Evidence boundary:** setup artifact proof is not client-runtime proof. It does
not prove a particular installed client loaded the configuration, emitted a hook
event, or routed a live action through HELM. When a separately verified adapter
submits a request to HELM, that adapter—not `setup`—is responsible for acting on
the `ALLOW`, `DENY`, or `ESCALATE` decision.
