---
title: How HELM Works
last_reviewed: 2026-07-01
---

# How HELM Works

HELM sits between an agent proposal and a real side effect. The public proof
path is local: load a policy, evaluate a proposed action, return `ALLOW`,
`DENY`, or `ESCALATE`, and write evidence that can be verified offline.

## Boundary

The boundary is the checkpoint before dispatch. A client, hook, wrapper, MCP
adapter, or OpenAI-compatible proxy sends the proposed action to HELM before
the action runs.

## Policy

Policies decide whether the action may proceed. Unknown, untrusted, or
unapproved paths fail closed: they deny or escalate instead of silently
continuing.

## Receipts

Each governed decision records a signed receipt. Receipts let a reviewer check
what was evaluated, which verdict was returned, and whether the record was
tampered with.

## EvidencePacks

EvidencePacks bundle receipt and proof material for offline verification. They
are evidence containers, not regulatory certifications or buyer rollout claims.

## What This Does Not Claim

HELM controls actions that cross a HELM adapter, hook, wrapper, proxy, or API
route. The public Kernel docs do not claim operating-system-wide enforcement,
hosted Enterprise automation, or provider-level model control.

## Evidence

- `docs/QUICKSTART.md`
- `docs/CONFORMANCE.md`
- `docs/VERIFICATION.md`
- `docs/reference/execution-boundary.md`
- `docs/reference/http-api.md`
- `core/cmd/helm-ai-kernel`
- `api/openapi/helm.openapi.yaml`
