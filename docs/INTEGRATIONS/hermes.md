---
title: Hermes
last_reviewed: 2026-08-19
---

# Hermes

Use HELM as a local pre-dispatch gate for Hermes tool calls. The shipped
path is the same Kernel setup used for Claude Code and Codex: MCP plus a
native `pre_tool_call` command. This is not a skill, not a console screen,
and not the `helm-agent-integrations` demo adapter.

```text
Hermes tool proposal
-> ~/.hermes/config.yaml pre_tool_call
-> helm-ai-kernel hook pre-tool --client hermes
-> ALLOW: tool runs
-> DENY: hook returns {"action":"block","message":"..."} and exit 2; receipt
   lands under ~/.helm-ai-kernel/receipts/hooks/
```

Hermes has no HELM DENY screen. A blocked tool is a native hook failure
returned to the model. Installing this target does **not** mean Hermes
already sees DENY in the wild. A stranger still must offline-verify a
signed hook receipt.

## Quick Setup

Hermes CLI and gateway load `~/.hermes/config.yaml`. Use user scope:

```bash
helm-ai-kernel setup hermes --scope user --yes
```

Inspect first:

```bash
helm-ai-kernel setup hermes --scope user --dry-run --json
```

Check what was written:

```bash
helm-ai-kernel setup status hermes --scope user
```

Remove the owned MCP server and hook, leaving other Hermes keys in place:

```bash
helm-ai-kernel setup remove hermes --scope user --yes
```

Setup writes:

- `mcp_servers.helm-ai-kernel-governance` pointing at `helm-ai-kernel mcp serve`
- `hooks.pre_tool_call` with matcher `^(terminal|write_file|patch|mcp__.*)$`,
  command `helm-ai-kernel hook pre-tool --client hermes`, and
  `fail_closed: true`

`fail_closed: true` is required. Without the hook entry, Hermes never
calls Kernel and the tool runs. A DENY path cannot be skipped by omitting
the hook and still claiming the gate is active.

## Verify a Hook Decision

Every classified DENY writes a signed receipt under:

```text
~/.helm-ai-kernel/receipts/hooks/
```

Verify one offline:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

This proves signature integrity against the receipt's self-declared key.
It does not claim a live Hermes session already observed the denial.

## Scope

This page covers the Kernel `setup hermes` hook only. It does not claim
upstream endorsement, a hosted Hermes runtime, a Grok adapter, or that
the OS is live.
