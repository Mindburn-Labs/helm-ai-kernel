---
title: HELM Proof Loop
last_reviewed: 2026-07-02
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
-> ESCALATE: action is blocked until a credential-verifying source records a scoped approval
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

Integrity and signer trust are separate verdicts here — trust is checked
against the local `--data-dir` workstation key by default, with
`--trusted-public-key-file` as the out-of-band pin for copied receipts
([details](reference/workstation-governance.md#local-signer-and-trusted-verification));
pre-v0.7.3 derivable-seed receipts remain untrusted.

## What Each Surface Owns

| Surface | Public role | Proof output |
| --- | --- | --- |
| Agent gateway | Routes actions before side effects run | verdict and receipt |
| Policy authoring | Defines allowed, denied, and escalated effects | policy ref in receipt |
| Scoped approval | Narrows an `ESCALATE` path when a source-owned verifier is configured | approval and revocation receipts |
| EvidencePack | Moves proof between machines | offline verifier result |
| Category pages | Explain adjacent tools without superiority claims | cited public evidence |

## Boundaries

- HELM only governs effects routed through an adapter, wrapper, hook, proxy, or
  API route.
- `ESCALATE` is not permission to continue. A source-owned verifier must issue
  any required approval before the original action can be rerun.
- Receipts prove the evaluated action and verdict. They do not prove every
  tool outside the boundary was governed.
- EvidencePacks are portable proof bundles, not marketing screenshots.

## Next

- [Quickstart](QUICKSTART.md)
- [Verification](VERIFICATION.md)
- [Export and verify EvidencePacks](guides/export-verify-evidencepacks.md)
- [HTTP API](reference/http-api.md)
