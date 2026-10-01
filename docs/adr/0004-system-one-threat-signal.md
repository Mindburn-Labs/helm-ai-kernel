# ADR 0004: Remote typed-decision threat signal (System One) is evidence that can only tighten admission

<!-- quantum_posture: this decision adds a stored evidence record and two reason
codes. It introduces no cryptographic primitive, no key handling and no
signature algorithm, and makes no post-quantum claim. -->

Status: Proposed (draft; spec text only, no implementation)
Date: 2026-09-29
Tracking: HELM-878 (Linear), ELEC-292 / ELEC-293 (Multica)

> **This ADR is not a specification of bytes.** Per
> [ADR 0003 §D8](0003-normative-artifact-arbitration.md) the normative sources
> are the Go contract types in `core/pkg/contracts`, the reason-code registry
> `protocols/json-schemas/reason-codes/reason-codes-v1.json` and the gateway
> proto. This record fixes the decision and the rules those sources must obey.

## Context

The R0 effect gateway admits an effect in one PostgreSQL transaction and
decides with a pure function (`core/pkg/gateway/admission/admission.go`,
`decide.go`; binding rules R5 and R7 in `AGENTS.md`). It carries no threat
signal today. The legacy Guardian chain carries a deterministic threat scan
with an advisory semantic slot (`core/pkg/threatscan`, CTL-019, enforced) that
the target architecture replaces with `decide` plus admission (TA §14.5).

The owner asked for TypeSafe's System One model (Jev) as an additional
security-threat check. It returns native probability distributions for typed
questions (`noul`, `choice`, `score`). Domain calibration is an independent
evaluation requirement; the distribution is not proof of threat or authority. The vendor documents that adversarial
content can move the answer, that accuracy falls with unrelated state, and that
thresholds do not transfer between primitives.

Binding rule R3 says model output can only propose and that content scanners
are inputs to policy, not gates. TA §0.2 item 7 says classifying content is
observed-only, never enforced. R12 says a new field in a signed payload is a
new payload version.

## Decision

1. **The signal is a sibling evidence record, not a verdict.**
   `contracts.RemoteThreatSignal` (with `RemoteThreatAnswer`) is added next to
   `SemanticThreatAssessment`. It records provider, pinned model version,
   question-set digest, the digest of the exact redacted state bytes sent,
   per-answer probabilities and confidence in integer basis points, latency,
   usage, availability and a closed set of failure reasons. Severity is derived
   by a fixed mapping in the kernel, never taken from the provider, and the
   remote signal never produces `CRITICAL`.

2. **Collected through the native model gateway before `decide`, persisted
   with admission, replayed from rows.** The future integration binds the
   tenant-scoped parent idempotency key and canonical input digest to a stable
   child model-call identity. Its admitted model call, reservation, provider
   attempt and settlement use the native gateway journal. The admission
   transaction stores the bound completed observation in
   `authority_attempt_signals`; it does not create a second provider client.
   `decide.Input.Signals` is data. A duplicate, parent rollback, re-admission on
   `Approve`, `Get` or verifier replay uses those persisted rows. An ambiguous
   provider outcome is recorded as unavailable and is not resent automatically.
   The exact parent/child transaction and recovery protocol remains an
   implementation contract with required PostgreSQL crash/replay tests; this
   proposal does not claim at-most-once behavior before those tests exist.

3. **Tighten-only.** `Decide` consults the signal after every deny check and
   the counters and before the approval switch. It can convert ALLOW into
   ESCALATE with one of the two reason codes below. It never converts DENY or
   ESCALATE into anything more permissive, and in this version it never
   produces DENY: DENY on a remote answer requires deterministic corroboration
   on the admission path, which does not exist yet, and is a later amendment
   to this ADR, not a configuration option. A required signal that is missing
   never yields ALLOW. The property "for every input, the outcome with the
   signal is never more permissive than without it" is a test.

4. **Two reason codes, additive, through the one registry (R4, HELM-747):**
   `THREAT_SIGNAL_ESCALATE` (ESCALATE, domain threat, finality
   instance_context: a remote typed-decision signal flagged the effect at or
   above the configured severity) and `THREAT_SIGNAL_UNAVAILABLE` (ESCALATE,
   domain threat, instance_context: a signal the policy requires for this risk
   class was not available; the record carries the failure reason). They are
   `reason_code_pending` in the gateway proto until the slice that emits them
   registers them.

5. **Signed payloads (R12).** Nothing on the admission path is DSSE-signed
   today. The signal enters the `authorization` payload type from its first
   version as `threat_signals` (signal kind, model version, question-set digest,
   input digest, availability, failure reason, flagged, max severity, answers
   digest). If `application/vnd.helm.authorization.v1+json` ships before the
   signal, the signal requires `v2` and `v1` stays verify-only. The legacy
   `ThreatScanRef` and the V3 decision preimage are not changed.

6. **Credential and egress (R8, CTL-048 pattern).** Provider credentials
   remain with the configured native model gateway. The threat collector and
   admission code receive only bound evidence and never obtain a provider key.
   Every state leaving the boundary passes `privacy.ProtectModelRequestJSON`;
   a privacy error means nothing is sent and the record says
   `PRIVACY_BOUNDARY_UNAVAILABLE`. The state is a bounded, redacted effect
   descriptor with a fixed size cap, never the raw payload. Hosted disclosure
   additionally requires the approved provider/data scope; local redaction
   alone does not approve disclosure.

7. **Control registry (R1).** The control is `observed-only` with the reason
   that classification of content is observed-only by design (TA §0.2 item 7);
   it has allowed, forbidden, removal and bypass tests, and it stays
   observed-only.

8. **One model gateway (R4, TA §8).** The inference is an admitted model
   effect with the existing native reservation and exact settlement path.
   Token counters alone cannot substitute for financial admission. There is no
   temporary direct TypeSafe client or alternate billing journal. If the native
   gateway, approved scope, reservation or bound settlement evidence is
   unavailable, the signal records an unavailable reason. Any policy requiring
   it applies the existing tighten-only unavailability rule. The completed
   signal references its canonical model attempt and settlement evidence.

## Alternatives rejected

- Extending `SemanticThreatAssessment` in place: its fields are integer cosine
  similarity against a hashed local model; a remote probabilistic answer does
  not fit, and the type is bound by the V3 decision preimage.
- Wiring the signal into the legacy Guardian interceptor chain: the chain is
  slated for replacement, and CTL-019 is enforced there; an unenforced signal
  inside an enforced control muddles the registry.
- Exposing an intermediate parent `PROPOSED` attempt or treating a provider
  reply as a completed observation before its native journal is bound. Parent
  admission remains atomic; the integration must prove recovery of its child
  model call without repeating egress or settling usage twice.
- A temporary direct provider route backed only by token counters: this would
  duplicate the model gateway and bypass the native exact-settlement boundary.
- Letting the remote signal deny alone: content would decide authority (R3).

## Consequences

- One new table under FORCE RLS, one new `EffectAttempt` field (additive), two
  new reason codes (additive), one new control entry (observed-only).
- Replay and the verifier read a stored record; no verification step calls a
  provider.
- The signal can add escalations and nothing else. Operators who require it for
  High and Irreversible risk classes accept that a provider outage turns those
  attempts into `THREAT_SIGNAL_UNAVAILABLE` escalations, which they already
  were by risk class.
- Provider data terms, calibration and latency are unproven by this record;
  it authorizes no production use.
