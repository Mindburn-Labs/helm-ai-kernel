---
title: HELM Proof Loop
last_reviewed: 2026-07-14
---

# HELM Proof Loop

HELM is useful only when the action reaches the boundary. The loop is small:
an agent proposes an action, HELM evaluates it before dispatch, the verdict is
`ALLOW`, `DENY`, or `ESCALATE`, and the run leaves evidence that can be checked
later.

```text
agent proposes action
-> HELM evaluates policy, approval state, and effect scope
-> ALLOW: action may dispatch
-> DENY: action is blocked
-> ESCALATE: action is blocked until a scoped approval exists
-> receipt and EvidencePack material can be verified offline
```

## One Local Path

Install the kernel, run the local proof, then verify the bundle:

```bash
brew tap mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> --profile dev-local --json
```

For one workstation receipt:

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

## What Each Surface Owns

| Surface | Public role | Proof output |
| --- | --- | --- |
| Agent gateway | Routes actions before side effects run | verdict and receipt |
| Policy authoring | Defines allowed, denied, and escalated effects | policy ref in receipt |
| Scoped approval | Narrows an `ESCALATE` path | approval and revocation receipts |
| EvidencePack | Moves proof between machines | offline verifier result |
| Category pages | Explain adjacent tools without superiority claims | cited public evidence |

## Native Setup Is A Separate Layer

Codex project setup adds a signed local lifecycle transaction around the
generated config. Its exact-config checks and Kernel-only synthetic denial are
useful local evidence, but `client_load_observed=false` means a real client has
not yet been observed. The next layer is a sterile native-client review that
exercises only configured hook classes and routed MCP calls; direct client or
upstream paths remain outside the evidence. See the [Native Client Integration
Boundary](INTEGRATIONS/native-client-boundary.md) for the public review limits.

## Boundaries

- HELM only governs effects routed through an adapter, wrapper, hook, proxy, or
  API route.
- `ESCALATE` is not permission to continue. Approve the exact scope, then rerun
  the original action.
- Receipts prove the evaluated action and verdict. They do not prove every
  tool outside the boundary was governed.
- EvidencePacks are portable proof bundles, not marketing screenshots.
- Native setup receipts do not prove a client session merely because the config
  and synthetic denial passed.

## Next

- [Quickstart](QUICKSTART.md)
- [Verification](VERIFICATION.md)
- [Export and verify EvidencePacks](guides/export-verify-evidencepacks.md)
- [HTTP API](reference/http-api.md)
