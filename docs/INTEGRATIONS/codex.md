---
title: Codex Integration
last_reviewed: 2026-07-14
---

# Codex Integration

Use HELM with Codex when you want a local MCP and hook setup that records signed
policy decision receipts for selected high-risk effects. It governs only the
configured hook classes and MCP calls routed through HELM.

## Quick Setup

```bash
helm-ai-kernel setup codex --yes
```

Project scope:

```bash
helm-ai-kernel setup codex --scope project --yes
```

Project scope keeps its binding, recovery journal, and generated artifacts in a
workspace-hash namespace below the selected data directory. The local signing
authority and receipt store remain shared. See the [native client integration
boundary](native-client-boundary.md) before moving or reusing local state.

Check user scope:

```bash
helm-ai-kernel setup status codex
```

Remove user scope:

```bash
helm-ai-kernel setup remove codex --yes
```

For a project-scope interruption, inspect and resume the recorded transaction
instead of rerunning setup or removal:

```bash
helm-ai-kernel setup status codex --scope project --json
helm-ai-kernel setup recover codex --scope project --yes
```

Pre-v1 unscoped project state requires an explicit migration operation:

```bash
helm-ai-kernel setup migrate codex --scope project --yes
```

`--dry-run` validates the full current legacy source-and-project-destination
snapshot without writing or reserving it; it is not a completed migration. With
`--yes`, HELM locks and revalidates before moving validated state into the v1
project namespace; a new binding destination is staged and validated before
publication. If source retirement cannot finish or fully roll back after
publication, the command reports sealed cleanup: v1 remains active authority
and the retained source copy is not. Inspect the project status after the move.

## Inspect Before Writing

```bash
helm-ai-kernel setup codex --dry-run --json
```

The dry run writes nothing and returns the target config paths, data dir, Kernel
URL, draft policy path, and uninstall command.

## Evidence Boundary

Project setup records exact local config snapshots, a signed lifecycle receipt,
and a Kernel-only synthetic denial. Its summary intentionally reports
`client_load_observed=false`: those checks do not prove that a real Codex
session loaded the config or blocked a client action. See the [native-client
integration boundary](native-client-boundary.md) for that separate review.

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
- `docs/INTEGRATIONS/native-client-boundary.md`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
