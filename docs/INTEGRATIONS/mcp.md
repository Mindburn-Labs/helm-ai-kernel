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

## Standalone Server Decision Receipts

`mcp serve --transport stdio` and `mcp serve --transport http` persist a signed
`receipt.v5` before a policy ALLOW can dispatch. Policy DENY decisions, including
the default with no `--policy`, use the same receipt writer. A failure to sign,
store, or export the receipt blocks dispatch. Protocol, authentication, and
argument-validation errors that occur before a policy decision do not issue a
decision receipt.

`--data-dir` selects the local SQLite database (`helm.db`), persistent signing
key (`root.key`), public trust anchor (`root.pub`), and portable receipt exports.
Each governed response's `receipt_id` identifies its persisted decision receipt.
The corresponding JSON is at
`<data-dir>/receipts/evaluate/<receipt_id>/<receipt_id>.json`.
Retain `root.pub` separately as your trust anchor, then verify with:

```bash
helm-ai-kernel verify receipt \
  --receipt <receipt.json> \
  --trusted-public-key-file <retained-root.pub>
```

The verifier reports which receipt members the signature covers. An ALLOW
receipt records admission; it does not prove that dispatch completed. An export
failure may leave the database decision row while the call remains blocked.

The standalone listener serves `HELM_RUNTIME_TENANT_ID` (default `default`).
Stdio takes this scope from trusted process configuration. HTTP binds validated
credentials to this configured tenant and rejects a conflicting tenant header
or signed OAuth tenant claim. Client arguments cannot select receipt scope.

This is bounded local storage. Postgres ledger integration, isolated signing-key
custody, and an upstream MCP proxy remain separate requirements. Back up the
SQLite database and retain the public trust anchor with the evidence you need.

## Generate A Wrapper Profile

```bash
helm-ai-kernel mcp wrap \
  --server-id helm-demo-shell \
  --upstream-command "npx -y shell-mcp-server" \
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
helm-risk-scan scan \
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
  --allow-self-attested \
  --json
```

The proof pack is sealed by a key carried inside the pack, so `verify` refuses
it without `--allow-self-attested`. With the flag the result proves internal
consistency, not who produced the pack.

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
