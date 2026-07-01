---
title: MCP
last_reviewed: 2026-07-01
---

# MCP

Use HELM as a pre-dispatch firewall for MCP tool calls.

```text
tools/list -> visible tools are filtered
tools/call -> HELM evaluates before dispatch
ALLOW -> call upstream
DENY -> block
ESCALATE -> block, write receipt, show scoped approval command
```

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

An unknown or unapproved server returns `ESCALATE`. The action is not
dispatched. Use the approval loop in [Quickstart](/quickstart#see-an-escalation).

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
