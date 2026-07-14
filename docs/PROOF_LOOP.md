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

## One 60-Second Local Path

Install the kernel, run the local proof, then verify the bundle:

```bash
brew tap mindburn-labs/tap
brew install helm-ai-kernel
helm-ai-kernel mcp proof --json --out ~/.helm-ai-kernel/proofs
helm-ai-kernel verify --bundle ~/.helm-ai-kernel/proofs/<run-id>/evidencepacks/<run-id> --profile dev-local --json
```

`mcp proof` runs both sides of the boundary in one deterministic sequence:

1. A pinned tool with a valid scoped approval writes one fixed file inside the
   proof output directory through the real `SafeExecutor` path.
2. Replaying the identical authorized effect returns the stored signed receipt;
   the local driver remains at one dispatch.
3. Missing and invalid approval paths, along with the remaining threat cases,
   produce `DENY` or `ESCALATE` receipts and never call the driver.
4. The command seals an EvidencePack, verifies it offline, mutates a copied
   pack, and requires that tampered copy to fail verification.
5. The command exits non-zero unless the complete proof finishes in under
   60 seconds. `12_REPORTS/60_second_gate.json` records the governed-scenario
   timing inside the sealed pack; `summary.json` records the complete command
   timing.

The effect is deliberately local and reversible: the only dispatched tool can
write the fixed `effects/reversible_effect.txt` path beneath that proof run.
The pack contains its content at `04_EXPORTS/reversible_effect.txt`, plus the
policy receipt, signed execution receipt, and replay tape. The replay guarantee
demonstrated here is sequential same-effect idempotency; it is not a claim of
concurrent or crash-recovery exactly-once execution.

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

## Boundaries

- HELM only governs effects routed through an adapter, wrapper, hook, proxy, or
  API route.
- `ESCALATE` is not permission to continue. Approve the exact scope, then rerun
  the original action.
- Receipts prove the evaluated action and verdict. They do not prove every
  tool outside the boundary was governed.
- EvidencePacks are portable proof bundles, not marketing screenshots.

## Next

- [Quickstart](QUICKSTART.md)
- [Verification](VERIFICATION.md)
- [Export and verify EvidencePacks](guides/export-verify-evidencepacks.md)
- [HTTP API](reference/http-api.md)
