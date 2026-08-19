---
title: Hermes
last_reviewed: 2026-08-19
---

# Hermes

Use HELM as a local pre-dispatch gate for Hermes tool calls. The shipped
path is a Kernel `setup hermes` shell hook, not MCP, not a skill, not a
console screen, and not the `helm-agent-integrations` demo adapter.

```text
Hermes tool proposal
-> ~/.hermes/config.yaml pre_tool_call
-> helm-ai-kernel hook pre-tool --client hermes
-> ALLOW: tool runs
-> DENY: hook returns {"action":"block","message":"..."} and exit 2; receipt
   lands under ~/.helm-ai-kernel/receipts/hooks/
```

Do not drop `--client claude-code` into Hermes config. That dialect writes
`hookSpecificOutput.permissionDecision=deny` and exits 0. Hermes does not
honor that shape, so the gate fails open.

Hermes has no HELM DENY screen. A blocked tool is a native hook failure
returned to the model. Installing this target does **not** mean Hermes
already sees DENY in the wild, and it does **not** mean DENY is visible
in the Hermes UI. A stranger still must offline-verify a signed hook
receipt.

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

Remove the owned hook (and any leftover HELM MCP entry from an earlier
revision), leaving other Hermes keys in place:

```bash
helm-ai-kernel setup remove hermes --scope user --yes
```

Setup writes `hooks.pre_tool_call` with:

- matcher `^(terminal|write_file|patch|mcp_.*)$` (Hermes tool names, plus
  MCP names as Hermes emits them: `mcp__server__tool` or older
  `mcp_server_tool`)
- command `helm-ai-kernel hook pre-tool --client hermes`
- `fail_closed: true`
- `timeout: 30`

It does not write `mcp_servers`. The Hermes MCP path is unverified; the
smallest hop is this shell hook.

`fail_closed: true` is required. Hermes shell hooks default fail-open.
Without the hook entry, Hermes never calls Kernel and the tool runs. A
DENY path cannot be skipped by omitting the hook and still claiming the
gate is active.

Unclassified tools are pass-through and write no receipt. The classifier
decides `terminal`, `write_file`, `patch`, and Hermes-emitted MCP names.

## First-use consent

Hermes uses a first-use hook allowlist. Setup writes the hook; it does
**not** write `hooks_auto_accept: true` (that would auto-accept every
hook). Without `--accept-hooks`, `HERMES_ACCEPT_HOOKS`, or
`hooks_auto_accept`, a non-TTY session never registers the hook.

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
