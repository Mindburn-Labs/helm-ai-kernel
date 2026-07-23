---
title: Codex Integration
last_reviewed: 2026-06-29
---

# Codex Integration

Use HELM with Codex when you want a local MCP and hook setup that records signed
policy decision receipts for selected high-risk effects.

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
That is the **integrity** check only: signer *trust* is a separate verdict
(`signer_trusted`), evaluated against an expected workstation public key —
the local `--data-dir` key by default, or an out-of-band pin via
`--trusted-public-key-file` for copied receipts — see
[local signer and trusted verification](../reference/workstation-governance.md#local-signer-and-trusted-verification).
Receipts signed with pre-v0.7.3 derivable seeds remain untrusted.

## Source Truth

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/setup_cmd_test.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
