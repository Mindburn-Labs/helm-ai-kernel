---
title: MCP
last_reviewed: 2026-07-15
---

# MCP

Use the current MCP surface to generate client configuration, inspect local
quarantine state, evaluate a scoped call before dispatch, revoke approval, and
produce receipt-backed no-dispatch evidence.

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
not dispatch the tool call. Opaque CLI or API approval fields cannot change that
result; a credential-verifying integration must record approval before the
server can leave quarantine. See the escalation walkthrough in
[Quickstart](/quickstart#see-an-escalation), then rerun the original configured
call path.

## Scan Quarantined Servers

Use the local MCP risk scanner to inspect a new server/tool bundle:

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

Approval metadata is not self-authenticating. The current CLI and API reject
opaque local approval assertions; only a credential-verifying integration may
create a TTL-bound, revocable approval record.

Side-effect tools therefore stay denied or escalated until that integration is
available and has issued a verified, scope-bound approval.

## Revoke

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-demo-shell \
  --reason "inspection finished"
```

Revoked and expired grants fail closed on the next configured evaluation.
Revocation does not create new authority.

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

The source-owned proof covers configuration generation, quarantine, scoped
authorization, expiry, revocation, no-dispatch behavior, receipts, and offline
verification. Approval remains unavailable until a credential-verifying
integration is configured. Before a live client rollout, separately prove:

- the native client loaded the generated configuration;
- the intended policy graph is wired into the selected MCP runtime;
- the exact tool call reaches the configured boundary;
- the allowed path has an explicit executor or upstream proxy;
- denied and escalated calls do not dispatch;
- schema drift, expired approval, and revocation fail closed; and
- the resulting receipt or EvidencePack verifies outside the client.
