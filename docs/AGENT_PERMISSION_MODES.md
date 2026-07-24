---
title: Agent Permission Modes
last_reviewed: 2026-07-21
---

<!-- quantum_posture: this page documents classical Ed25519 receipt signing and does not claim post-quantum or hybrid cryptographic protection. -->

# Agent Permission Modes

Most agent runtimes ask before they act: a prompt appears, a human answers, the
action proceeds. That is a real control. At one operator, one agent, one
keyboard, it is often the only control needed.

This page describes where that mechanism stops and what HELM adds. It compares
mechanism classes, not named tools.

| Property | Per-action permission prompt | HELM AI Kernel |
| --- | --- | --- |
| Enforcement site | inside the runtime being governed | a boundary the effect must cross |
| Grant shape | standing permission, once answered | permit bound to connector, action, parameters, resource |
| Reuse | persists until revoked | single-use, expiring, nonce-checked |
| Artifact | none defined | signed receipt, verifiable offline |
| Unattended runs | no answer available | verdict resolves without a human present |
| Failure behavior | varies by runtime | unable to sign a receipt, deny |

## What a Permission Prompt Governs

A permission prompt gates what that runtime is about to do, at the moment it does
it. Its scope is the runtime's own action set. Its authority is the operator
sitting in front of it.

Two consequences follow from the shape of the mechanism rather than from any
implementation of it.

**Answering is a grant, not a binding.** "Allow this action" tends to become
"allow actions like this," and the allowance persists. The permitted set grows
monotonically and is rarely reviewed downward.

**Attention is the limiting resource.** A study of experienced developers
overseeing coding agents found real-time monitoring is
[rarely performed](https://arxiv.org/html/2606.05391), with oversight running on
satisficing heuristics because the systems are "too fast, too complex, and too
much for users." A randomized experiment (n=2,784) found people are
[less likely to correct erroneous AI suggestions](https://www.nature.com/articles/s41598-026-34983-y)
when correcting them requires extra effort. EU AI Act
[Article 14](https://artificialintelligenceact.eu/article/14/) treats this as a
design constraint: overseers must be able to counter automation bias, disregard
or override output, and halt the system.

A prompt asks a human for attention. It does not create the attention.

## Where HELM Differs

HELM decides from policy at a boundary the effect must cross, then writes a
signed record of the decision.

- **Bound permits, not standing grants.** An `EffectPermit` names one connector,
  one action, one parameter set, one resource, with an expiry and a single-use
  nonce. An identical re-dispatch is caught as a replay.
- **An artifact a third party can check.** Each decision produces a signed
  receipt. The offline verifier trusts only Ed25519, SHA-256, and JCS — not the
  network, not an account, not the process that issued the receipt.
- **A verdict without a human present.** Scheduled work, unattended runs, and
  delegated sub-agents have nobody to prompt. Policy still resolves.
- **A defined failure direction.** If a signed receipt cannot be produced, the
  operation is denied rather than allowed.

## HELM's Narrow Claim

HELM governs effects that reach its boundary. It does not govern actions a
runtime takes without routing them, and it is not a model-layer control against
prompt manipulation.

Coverage differs by effect class. See
[Workstation governance](reference/workstation-governance.md) for the per-class
boundary, including the deliberately narrow shell guard.

The claim is not that HELM understands every action. It is that what HELM cannot
establish as permitted does not pass.

## Comparison Rules

- Compare mechanism classes, not named tools or their current behavior.
- Say "different scope" before saying "better".
- A permission prompt is a real control; do not argue it is worthless.
- Name the routed action and proof artifact for any HELM claim.
- Do not imply HELM governs an action that never crossed the boundary.

## Useful Reading

- [Workstation governance](reference/workstation-governance.md)
- [HELM Proof Loop](PROOF_LOOP.md)
- [Verification](VERIFICATION.md)
