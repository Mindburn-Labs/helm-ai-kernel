---
title: How HELM Works
last_reviewed: 2026-08-21
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

`ESCALATE` means HELM blocked the action and wrote a receipt. Nothing
dispatches on `ESCALATE`. Local `helm-ai-kernel mcp approve` does not mint
approval authority; a credential-verified durable dispatch admission from the
governing approval integration is required before re-evaluation. HELM never
continues the original action silently.

## Approvals

Bounded MCP dispatch requires a credential-verified durable admission. Opaque
local approver strings, receipt ids, tool lists, and TTLs are not executable
authority. When a verifier-backed grant exists, scope stays narrow:

- exact server id
- exact tool list
- explicit effect scope
- required reason
- TTL-bound
- receipt-backed
- revocable

Read-only is the default effect. Write, deploy, network, and payment effects
must be admitted explicitly and use a shorter TTL. Ceremony decisions in the
operator TUI require typing `APPROVE` or `DENY`; a click never decides.

## Receipts

Decision, approval, and revocation receipts live under
`~/.helm-ai-kernel/receipts/`. They are the public proof surface: inspect them,
export them, or include them in an EvidencePack for offline verification.

## Boundaries

HELM governs effects that cross a HELM adapter, hook, wrapper, proxy, or API
route. Anything outside those configured paths is outside the public Kernel
contract.
