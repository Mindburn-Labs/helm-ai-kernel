---
title: DeepSeek Harness
last_reviewed: 2026-08-20
---

# DeepSeek Harness

Use HELM as a local pre-dispatch hop under DeepSeek Harness (DSH). Kernel is
not a new harness. The shipped path is a Kernel-owned hook file plus a DSH
profile row that points `configPath` at that file, so stock
`@deepseek-ai/dsh-hooks-claude-code` (and, when already present,
`@deepseek-ai/dsh-hooks-codex`) actually load it.

This is not a Cordis plugin we ship. DSH treats everything as a plugin; a
HELM Cordis plugin can be unmounted and is not the hop. Setup uses DSH's
existing stock hook-bridge plugins only.

```text
DSH tool proposal (lowercase names: bash, write, edit, …)
-> $DSH_HOME/cordis.patch.yml insert row
   configPath -> ~/.dsh/helm-ai-kernel-hooks.json
-> stock dsh-hooks-claude-code tools/pre-execute
-> helm-ai-kernel hook pre-tool --client deepseek
-> ALLOW: tool runs
-> DENY: hook returns Claude-shaped
   hookSpecificOutput.permissionDecision=deny with hookEventName=PreToolUse
   and exit 0; the stock bridge maps merged.decision === 'deny' to a block.
   A signed receipt lands under ~/.helm-ai-kernel/receipts/hooks/
```

Do not drop `--client hermes` into this hop. Hermes `{"action":"block"}` plus
exit 0 is not a DSH block. Do not use an uppercase-only Claude matcher
(`Bash`/`Write`); DSH tool names are lowercase (`bash`/`write`) and that
matcher silent-misses them.

DSH has no HELM DENY screen. Installing this target does **not** mean DSH
already sees DENY in the wild, does **not** mean DENY is visible in the DSH
UI or stock DSH web, and does **not** mean a stranger observed the block. A
stranger still must offline-verify a signed hook receipt. Proof of this hop
is NO-GO until that verification exists.

## Quick Setup

Stock DSH loads `$DSH_HOME/cordis.patch.yml` (or `~/.dsh` when `DSH_HOME` is
unset). `configPath` is process-level. Use user scope:

```bash
helm-ai-kernel setup deepseek --scope user --yes
```

If `--scope` is omitted, setup coerces the install default (`project`) to
`user`. Explicit `--scope project` is rejected: DSH has no workspace patch
auto-load for this hop.

Inspect first:

```bash
helm-ai-kernel setup deepseek --scope user --dry-run --json
```

Check what was written:

```bash
helm-ai-kernel setup status deepseek --scope user
```

Remove the owned hook command and owned profile rows, leaving other patch
entries in place:

```bash
helm-ai-kernel setup remove deepseek --scope user --yes
```

Setup writes two things. The hook file alone is dead:

- `~/.dsh/helm-ai-kernel-hooks.json` (or `$DSH_HOME/…`) with a `PreToolUse`
  command `helm-ai-kernel hook pre-tool --client deepseek` and matcher
  `^(bash|pwsh|write|edit|str_replace_editor|terminal_open|terminal_send|terminal_signal)$`
- an insert row in `$DSH_HOME/cordis.patch.yml` for
  `@deepseek-ai/dsh-hooks-claude-code` whose `config.configPath` is the
  absolute Kernel hook file. If a Codex bridge row already exists, setup
  points that row at the same file. It does not insert
  `@deepseek-ai/dsh-hooks-codex` on a blank profile, because an unresolved
  plugin name fails DSH boot.

It does not write MCP. DSH does not consume Kernel MCP the way Claude Code
does; the hop is this hook+profile mapping.

`dsh-hooks-claude-code` is **not** in `dsh-base`. Stock DSH does not see
Kernel DENY until a profile row sets `configPath` to the Kernel hook file
and the stock bridge is actually a profile dependency that boots.

Unclassified tools (`read`, `str_replace_editor` with `command=view`) are
pass-through and write no receipt.

## First-use caveats

- Ensure stock `@deepseek-ai/dsh-hooks-claude-code` is a DSH profile
  dependency, then restart `dsh` so it reloads `configPath`.
- Unsetting the profile row, pointing `configPath` at a missing file, or
  never installing the stock bridge fail-opens: the bridge logs and
  registers nothing, and DSH never calls Kernel.
- `configPath` is parsed once at load and is process-level. Relative paths
  resolve against the process launch cwd, not the session workspace.
- This does not mean DENY is visible in the DSH UI.

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
It does not claim a live DSH session already observed the denial.

## Scope

This page covers the Kernel `setup deepseek` hop only. It does not claim
upstream endorsement, a hosted DSH runtime, or that the OS is live.
