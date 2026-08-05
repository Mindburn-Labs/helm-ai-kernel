---
title: MCP
last_reviewed: 2026-07-15
---

# MCP

Use the current MCP surface to generate client configuration, inspect local
quarantine state, evaluate a scoped call before dispatch, revoke local MCP
records, and produce receipt-backed no-dispatch evidence.

The public commands do **not** yet prove a general-purpose upstream MCP proxy.
`mcp wrap` emits a wrapper profile; it does not launch the upstream command.
Generated client configuration also does not prove that a native client loaded
HELM or that arbitrary tool calls cross the boundary.

## Generate A Wrapper Profile

```bash
helm-ai-kernel mcp wrap \
  --server-id helm-demo-shell \
  --upstream-command "npx -y shell-mcp-server" \
  --require-pinned-schema=true \
  --json
```

Treat the JSON as configuration input to inspect and install through the owning
client. Do not treat this command as a running proxy.

## Generate Client Configuration

Print a configuration without changing the client:

```bash
helm-ai-kernel mcp print-config --client codex
helm-ai-kernel setup claude-code --dry-run --json
```

Generate the Claude Code plugin and MCP configuration artifacts:

```bash
helm-ai-kernel mcp install --client claude-code
```

The install command writes the local artifacts and prints the separate
`claude plugin install` command. Run and verify that client-owned step yourself.
Setup does not approve detected tools.

## Authorize Before Dispatch

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-demo-shell \
  --tool-name pwd
```

An unknown or unapproved server returns `ESCALATE`. The authorization check does
not dispatch the tool call. Credential verification is not wired to this local
CLI, so it cannot approve the server; it remains quarantined.

## Scan Before Credential-Verified Approval

Use the local MCP risk scanner before granting a new server/tool bundle:

```bash
mkdir -p out
helm-ai-kernel scan \
  --path . \
  --risk-envelope out/risk-envelope.json \
  --preview out/risk-report.md
```

For API clients, the same public surface is exposed as
`POST /api/v1/mcp/scan`. A scan is advisory: it records the detected surface and
does not dispatch, approve, or resume a tool call.

## Effect Scope

Raw local approver fields, receipt identifiers, tool lists, and TTLs are not
executable authority. `helm-ai-kernel mcp approve` returns an approval
verification-unavailable error until a credential verifier is wired to the
governing approval authority. No local command can turn a receipt string into
an allowed MCP server or side-effect grant.

## Revoke

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-demo-shell \
  --reason "inspection finished"
```

Revoked records fail closed on the next configured evaluation. Credential-
verified grants and their expiry semantics require a verifier-backed runtime
integration.

## Inspect And Prove

```bash
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel mcp get --server-id helm-demo-shell --json
```

Run the local no-dispatch proof:

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
```

Verify the emitted EvidencePack offline:

```bash
helm-ai-kernel verify \
  --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> \
  --profile dev-local \
  --json
```

## Current Boundary

The source-owned proof covers configuration generation, quarantine, no-dispatch
behavior, receipts, and offline verification. It does not demonstrate a
credential-verified MCP approval or allowed side-effect path. Before a live
client rollout, separately prove:

- the native client loaded the generated configuration;
- the intended policy graph is wired into the selected MCP runtime;
- credential verification binds approval to the exact server, tool, and effect;
- the exact tool call reaches the configured boundary;
- the allowed path has an explicit executor or upstream proxy;
- denied and escalated calls do not dispatch;
- schema drift, verified-grant expiry, and revocation fail closed; and
- the resulting receipt or EvidencePack verifies outside the client.
