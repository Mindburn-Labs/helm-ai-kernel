---
title: MCP
last_reviewed: 2026-07-15
---

# MCP

Use HELM to produce local MCP profile, configuration, approval, and
authorization artifacts. A runtime adapter must deliberately route a tool call
through that boundary before it can govern an upstream call.

```text
mcp wrap -> emits an execution-firewall profile for an upstream command or URL
mcp print-config / mcp install -> emits or creates client configuration artifacts
mcp authorize-call -> evaluates one local request and records its verdict
ALLOW -> authorization result; a separately verified adapter may decide whether to dispatch
DENY / ESCALATE -> this CLI does not dispatch
```

**Evidence boundary:** `mcp wrap` and `mcp authorize-call` do not launch,
proxy, or invoke an upstream MCP server. An `ALLOW` is an authorization result,
not an upstream-dispatch receipt.

## Wrap A Server

```bash
helm-ai-kernel mcp wrap \
  --server-id helm-demo-shell \
  --upstream-command "npx -y shell-mcp-server" \
  --require-pinned-schema=true \
  --json
```

Print or install client config:

```bash
helm-ai-kernel mcp print-config --client codex
helm-ai-kernel mcp install --client claude-code
```

## Authorize Before Dispatch

```bash
helm-ai-kernel mcp authorize-call \
  --server-id helm-demo-shell \
  --tool-name pwd
```

An unknown or unapproved server returns `ESCALATE`, writes the local decision
receipt, and does not dispatch the action. `ALLOW` still does not invoke the
upstream server; the caller must use a separately verified adapter to do that.
Use the approval loop in [Quickstart](/quickstart#see-an-escalation).

## Scan Before Approval

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
does not dispatch, approve, or resume any tool call.

## Effect Scope

Approvals are local, receipt-backed, TTL-bound, and revocable. HELM rejects
wildcard tool approvals and overlong side-effect approvals.

For side-effect tools, approve the effect explicitly:

```bash
helm-ai-kernel mcp approve \
  --server-id deploy-tools \
  --tools deploy.preview \
  --effects side_effect \
  --ttl 15m \
  --reason "preview deploy for local validation"
```

## Revoke

```bash
helm-ai-kernel mcp revoke \
  --server-id helm-demo-shell \
  --reason "inspection finished"
```

Revoked and expired grants fail closed on the next evaluation.

## Inspect

```bash
helm-ai-kernel mcp pending --json
helm-ai-kernel mcp receipts --json
helm-ai-kernel mcp get --server-id helm-demo-shell --json
```

Run the no-dispatch proof:

```bash
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
```

## What Still Blocks

HELM denies mismatched scopes, expired or revoked approvals, schema drift,
side-effect scope mismatch, and policy-forbidden actions. Missing approval or
unknown tool/server state escalates only when a developer can resolve it with a
local scoped approval or schema review.
