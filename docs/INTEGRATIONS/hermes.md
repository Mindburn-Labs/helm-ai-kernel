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

- matcher `^(terminal|write_file|patch|read_file|search_files|web_extract|execute_code|browser_navigate|vision_analyze|mcp_.*)$`
  (Hermes tool names, plus MCP names as Hermes emits them:
  `mcp__server__tool` or older `mcp_server_tool`)
- command `helm-ai-kernel hook pre-tool --client hermes`
- `fail_closed: true`
- `timeout: 30`

It does not write `mcp_servers`. The Hermes MCP path is unverified; the
smallest hop is this shell hook.

`fail_closed: true` is required. Hermes shell hooks default fail-open.
Without the hook entry, Hermes never calls Kernel and the tool runs. A
DENY path cannot be skipped by omitting the hook and still claiming the
gate is active.

A read of an ordinary file and a write to an ordinary file pass without a
receipt. The classifier decides `terminal`, `write_file`, `patch`, a
`read_file` or `search_files` call on a credential path or with a `file_glob`
that selects credential or key files, `web_extract` and `browser_navigate` as
network egress to their URL, `vision_analyze` as a read when `image_url` is a
local file and as network egress otherwise, `execute_code` as a shell
operation (the code is not a command line the hook can read; it needs
`shell.operate`), and Hermes-emitted MCP names. A `vision_analyze` image named
by a relative path that does not exist in the working directory is taken as a
host; pass an absolute path for a local image. A tool it has no class for is
decided as an unclassified tool call, which the default profile denies.

These Hermes tools are not routed, so the hook never sees them:
`web_search` (it names no URL), and `skill_manage`, `memory`,
`cronjob_manage` and `process_manage`, which the hook has no class for; what
they do is not decided. An install made by an earlier
release keeps its narrower matcher until `helm-ai-kernel setup hermes --yes`
is run again; `setup status` reports it as outdated. `setup status` reads a
Hermes matcher as a regular expression that may match anywhere in the tool
name; if Hermes anchors the matcher, or reads a plain name exactly, it routes
no more tools than `setup status` reports and may route fewer.

## First-use consent

Hermes uses a first-use hook allowlist. Setup writes the hook; it does
**not** write `hooks_auto_accept: true` (that would auto-accept every
hook). Without `--accept-hooks`, `HERMES_ACCEPT_HOOKS`, or
`hooks_auto_accept`, a non-TTY session never registers the hook.

## Coverage

This hook is an **observed-only** integration: it classifies the calls the
client sends it, signs a receipt for each decision, and denies what it
recognizes or cannot evaluate statically. It is defense in depth, not an
enforced boundary. See
[the coverage label](../reference/workstation-governance.md#coverage-label-observed-only).

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
