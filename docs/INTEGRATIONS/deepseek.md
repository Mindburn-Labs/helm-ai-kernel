---
title: DeepSeek
last_reviewed: 2026-08-19
---

# DeepSeek

Use HELM as a local pre-dispatch gate for DeepSeek Harness tool calls. The
shipped path is a Kernel `setup deepseek` hook plus a DSH profile
`configPath`, not MCP, not a Cordis plugin, and not a DeepSeek Harness
plugin that Kernel mounts into.

```text
DeepSeek tool proposal
-> ~/.dsh/cordis.patch.yml configPath
-> ~/.dsh/hooks.json PreToolUse
-> helm-ai-kernel hook pre-tool --client deepseek
-> ALLOW: tool runs
-> DENY: hook returns {"kind":"deny","reason":"..."} and exit 2; receipt
   lands under ~/.helm-ai-kernel/receipts/hooks/
```

Do not drop `--client claude-code` into the DeepSeek hook file. That dialect
writes `hookSpecificOutput.permissionDecision=deny` and exits 0. That is
not the DeepSeek adapter deny shape, so the gate fails open.

DeepSeek Harness has no HELM DENY screen in this path. Installing this
target writes the hook file and points the DSH profile `configPath` at it.
It does **not** mean `npx @deepseek-ai/dsh web` already sees DENY. A
stranger still must offline-verify a signed hook receipt.

## Quick Setup

DeepSeek Harness loads `$DSH_HOME` when that path is absolute, otherwise
`~/.dsh`. Use user scope:

```bash
helm-ai-kernel setup deepseek --scope user --yes
```

Inspect first:

```bash
helm-ai-kernel setup deepseek --scope user --dry-run --json
```

Check what was written:

```bash
helm-ai-kernel setup status deepseek --scope user
```

Remove the owned hook and profile `configPath`, leaving other DSH profile
rows in place:

```bash
helm-ai-kernel setup remove deepseek --scope user --yes
```

Setup writes two files:

1. `hooks.json` `hooks.PreToolUse` with:
   - matcher `^(bash|write|edit|mcp_.*)$` (DeepSeek lowercase tool names)
   - command `helm-ai-kernel hook pre-tool --client deepseek`
   - `fail_closed: true`
   - `timeout: 30`
2. `cordis.patch.yml` with `dsh-hooks-claude-code.configPath` set to the
   absolute hook file path. Without `configPath`, DSH registers no hooks
   and the hook file is dead.

It does not write MCP. Kernel is the hop; this is not a Cordis/DeepSeek
Harness plugin.

`fail_closed: true` is required for Kernel to treat the hook as installed.
Without the hook entry, or without a profile `configPath` that points at
that file, Kernel never sees the tool call and the tool runs.

Unclassified tools are pass-through and write no receipt. The classifier
decides `bash`, `write`, `edit`, and MCP names that start with `mcp_`.

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
It does not claim a live DeepSeek Harness session already observed the
denial.

## Scope

This page covers the Kernel `setup deepseek` hook and profile only. It
does not claim upstream endorsement, a hosted DeepSeek runtime, live/GA
proof, or that `npx @deepseek-ai/dsh web` sees DENY.
