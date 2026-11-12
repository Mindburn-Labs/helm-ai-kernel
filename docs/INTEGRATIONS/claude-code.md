---
title: Claude Code Integration
last_reviewed: 2026-06-29
---

# Claude Code Integration

Use HELM with Claude Code when you want local PreToolUse decisions and signed
receipts for selected high-risk tool effects.

## Quick Setup

```bash
helm-ai-kernel setup claude-code --yes
```

Check what was installed:

```bash
helm-ai-kernel setup status claude-code
```

Undo the local integration:

```bash
helm-ai-kernel setup remove claude-code --yes
```

## Inspect Before Writing

```bash
helm-ai-kernel setup claude-code --dry-run --json
```

The JSON summary includes the binary path, client config path, hook config path,
data dir, Kernel URL, draft policy path, and uninstall command.

## Verify a Hook Decision

The installed matcher routes `Bash`, `Edit`, `Write`, `MultiEdit`,
`NotebookEdit`, `Read`, `Grep`, `Glob`, `WebFetch`, `ReadMcpResourceTool`,
`ListMcpResourcesTool` and `mcp__*` calls to the hook. An install made by an
earlier release keeps its narrower matcher until
`helm-ai-kernel setup claude-code --yes` is run again; `setup status` reports
such a matcher as outdated (`hook_matcher_outdated`, with the tools no entry
that holds the HELM hook routes in `hook_matcher_missing_tools`), prints the
command that upgrades that install (`hook_matcher_upgrade_command`, with its
`--scope`, `--workspace` and `--data-dir`) and exits non-zero. It reads every
entry that holds the HELM hook (`hook_matchers`), and reads a matcher as
Claude Code does: one made only of letters, digits, `_` and `|` is a list of
exact tool names, so `Edit|Write` does not route `MultiEdit`; any other
matcher is a regular expression that may match anywhere in the name. When the
HELM hook shares a hook entry with another hook, setup leaves that entry's
matcher alone and prints a warning that names the file and the matcher.

These tools are not routed, so the hook never sees them:

- `WebSearch`: it names no URL, so the hook could only refuse it.
- `Task`: it starts a subagent; the subagent's own tool calls reach the hook.
- `TodoWrite`: it edits the client's own task list.

A tool you add to the matcher yourself is decided as an unclassified tool
call, which the default profile denies. Every classified PreToolUse decision,
whether allowed or denied, writes a signed receipt under:

```text
~/.helm-ai-kernel/receipts/hooks/
```

Verify one:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

This proves signature **integrity** against the receipt's self-declared key.
Signer **trust** (`signer_trusted`) is evaluated against an expected
workstation public key — the local `--data-dir` key by default; pin the
signer's key out of band with `--trusted-public-key-file` when verifying
copied receipts — see
[local signer and trusted verification](../reference/workstation-governance.md#local-signer-and-trusted-verification).
Receipts signed with pre-v0.7.3 derivable seeds remain untrusted.

## Coverage

This hook is an **observed-only** integration: it classifies the calls the
client sends it, signs a receipt for each decision, and denies what it
recognizes or cannot evaluate statically. It is defense in depth, not an
enforced boundary. See
[the coverage label](../reference/workstation-governance.md#coverage-label-observed-only).

## Deny Feedback Format

Every PreToolUse denial returns model-actionable steering text in
`hookSpecificOutput.permissionDecisionReason`, not just "denied":

```text
HELM denied <class>: <KERNEL_REASON_CODE> (receipt: <path>) [INBOX_KERNEL_POLICY_DENY] kernel=<CODE> <explanation> Remediation: <what to do instead> Escalation: <who can unblock>
```

- `[INBOX_*]` is the machine-readable steering code (namespaced so it cannot
  be confused with canonical Kernel verdict reason codes).
- `Remediation` tells the agent how to self-correct; `Escalation` names the
  human route. Agents should not retry an identical denied call.
- After 3 consecutive identical denied hook outcomes in one session, the
  doom-loop circuit breaker appends `[INBOX_DOOM_LOOP_DETECTED]` escalation
  guidance to the denial. The latch is per call signature: a changed
  approach is evaluated fresh. Policy denials and fail-closed infrastructure
  denials count; allowed calls never trip the breaker and reset the run.
  Breaker state lives under `<data-dir>/state/hook-doomloop.json` (bounded,
  lock-serialized); it is advisory
  steering on top of the authoritative policy path — the session ID is
  client-supplied and unauthenticated, so the breaker is not a security
  boundary. Payloads without a session ID are not tracked, so unrelated
  sessionless invocations can never false-trip each other.
- Fail-closed infrastructure denials carry their own codes:
  `[INBOX_SIGNER_UNAVAILABLE]`, `[INBOX_POLICY_PROFILE_UNAVAILABLE]`,
  `[INBOX_RECEIPT_PERSISTENCE_UNAVAILABLE]`.

## MCP Configuration

For lower-level MCP configuration, install the Claude Code MCP server:

```bash
helm-ai-kernel mcp install --client claude-code
```

Claude Desktop bundle output is separate:

```bash
helm-ai-kernel mcp pack --client claude-desktop --out helm-ai-kernel.mcpb
```

## Implementation

- `core/cmd/helm-ai-kernel/setup_cmd.go`
- `core/cmd/helm-ai-kernel/hook_cmd.go`
- `core/cmd/helm-ai-kernel/mcp_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/QUICKSTART.md`
- `docs/reference/cli.md`
