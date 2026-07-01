---
title: How HELM Works
last_reviewed: 2026-07-01
---

# How HELM Works

HELM is a local execution firewall for AI agents. A client, hook, wrapper, MCP
adapter, or OpenAI-compatible proxy sends a proposed action to HELM before the
action runs.

```text
agent/tool requests action
-> HELM evaluates before dispatch
-> ALLOW: action runs
-> DENY: action is blocked
-> ESCALATE: action is blocked and a decision receipt is written
```

## Verdicts

`ALLOW` means the proposed action matched the active policy and any required
approval scope.

`DENY` means the action is unsafe, mismatched, expired, revoked, outside scope,
or policy-forbidden.

`ESCALATE` means a developer can safely resolve the block with an exact local
approval. HELM writes a receipt and returns a short approval hint. It never
continues the original action silently.

## Approvals

Approvals are local-first and narrow:

- exact server id
- exact tool list
- explicit effect scope
- required reason
- TTL-bound
- receipt-backed
- revocable

Read-only is the default effect. Write, deploy, network, and payment effects
must be approved explicitly and use a shorter TTL.

## Receipts

Decision, approval, and revocation receipts live under
`~/.helm-ai-kernel/receipts/`. They are the public proof surface: inspect them,
export them, or include them in an EvidencePack for offline verification.

## Boundaries

HELM governs effects that cross a HELM adapter, hook, wrapper, proxy, or API
route. The public Kernel docs do not claim full operating-system control,
hosted Enterprise automation, provider-level model control, or buyer rollout
status.
