---
title: Codex Integration
last_reviewed: 2026-07-16
---

# Codex Integration

Use HELM with Codex when you want a local MCP and hook setup that records signed
policy decision receipts for selected high-risk effects.

## User-Scoped Quick Setup

```bash
helm-ai-kernel setup codex --yes
```

Check or remove the user-scoped integration:

```bash
helm-ai-kernel setup status codex
helm-ai-kernel setup remove codex --yes
```

## HELM Desktop Project Connection

The Desktop bridge uses a project-scoped, headless Codex setup. Project scope
requires an explicit `--workspace`; Desktop supplies an absolute selected
workspace and a selected local `--data-dir`.

Preview the exact plan before any file is written:

```bash
helm-ai-kernel setup codex \
  --scope project \
  --workspace /absolute/path/to/project \
  --data-dir /absolute/path/to/helm-state \
  --no-quickstart \
  --json \
  --dry-run
```

Apply that plan only after the preview has been reviewed:

```bash
helm-ai-kernel setup codex \
  --scope project \
  --workspace /absolute/path/to/project \
  --data-dir /absolute/path/to/helm-state \
  --no-quickstart \
  --json \
  --yes
```

`--no-quickstart` keeps this path headless: it starts no Quickstart server,
reports `quickstart_started: false`, and returns no fixed `kernel_url`. Codex
launches the configured HELM MCP server over stdio instead.

Inspect or remove the same project connection with the same workspace and data
directory:

```bash
helm-ai-kernel setup status codex \
  --scope project \
  --workspace /absolute/path/to/project \
  --data-dir /absolute/path/to/helm-state \
  --no-quickstart \
  --json

helm-ai-kernel setup remove codex \
  --scope project \
  --workspace /absolute/path/to/project \
  --data-dir /absolute/path/to/helm-state \
  --no-quickstart \
  --json \
  --yes
```

### What The Project Connection Changes

- The preview is read-only: it returns the target paths and planned actions,
  but creates neither the selected data directory nor Codex configuration.
- Apply writes scan and draft-only artifacts below
  `<data-dir>/autoconfigure/`, then adds HELM's
  `[mcp_servers.helm-ai-kernel-governance]` entry to
  `<workspace>/.codex/config.toml` and one HELM `PreToolUse` command to
  `<workspace>/.codex/hooks.json`.
- The Codex hook matches `Bash`, `apply_patch`, and `mcp__.*` tool names. It is
  not a claim that every Codex action is covered.
- Existing model settings, other MCP servers, and other hooks are preserved.
  A malformed existing Codex TOML file fails closed rather than being
  overwritten. Remove deletes only HELM's MCP entry and HELM hook command.
- Setup writes draft policy and inventory artifacts; it does not approve tools
  or grant operating permissions.

### What It Does Not Prove

This local configuration lifecycle does not prove that a Codex app has loaded,
reloaded, or trusted the project files; that a configured tool invocation has
reached HELM; or that a policy decision has governed an action at runtime. It
also does not establish hosted control-plane, database, provider, deployment,
or general-availability status. Run an explicit Codex runtime exercise and
verify its resulting receipt for those separate claims.

## User-Scoped Inspect Before Writing

```bash
helm-ai-kernel setup codex --dry-run --json
```

The dry run writes nothing and returns the target config paths, data dir, Kernel
URL, draft policy path, and uninstall command.

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

## Source Truth

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/setup_cmd_test.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
