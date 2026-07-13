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

`ESCALATE` means HELM blocked the action and wrote a decision receipt. For MCP,
the bundled CLI and API cannot resolve the block with local approval metadata:
the server remains quarantined until a credential-verifying integration is
configured. HELM never continues the original action silently.

## Credential-verified approvals

The bundled MCP approval surface does not create grants or approval receipts.
When a credential-verifying integration is available, its approvals must be
narrow:

- exact server id
- exact tool list
- explicit effect scope
- required reason
- TTL-bound
- verifier- and receipt-backed
- revocable

Read-only is the default effect. Write, deploy, network, and payment effects
must be verifier-approved explicitly and use a shorter TTL.

## Receipts

Decision and revocation receipts live under `~/.helm-ai-kernel/receipts/`.
They are the public proof surface: inspect them, export them, or include them
in an EvidencePack for offline verification. A future credential-verifying
integration may add approval receipts; the bundled MCP approval surface does
not.

## Boundaries

HELM governs effects that cross a HELM adapter, hook, wrapper, proxy, or API
route. Anything outside those configured paths is outside the public Kernel
contract.
