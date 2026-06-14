---
title: Receipt Comparison — AAR/Pipelock vs IETF ACTA vs HELM
last_reviewed: 2026-06-14
---

# Receipt Comparison — AAR/Pipelock vs IETF ACTA vs HELM Receipt v1.0

## Audience

Maintainers and reviewers positioning the HELM receipt against two adjacent
signed-receipt designs: the **AAR / Pipelock** agent-action receipt model, and the
IETF Internet-Draft **draft-farley-acta-signed-receipts-01** ("Agent Compliance
& Transparency Architecture" signed receipts). The goal is to know, primitive by
primitive, where HELM already matches or exceeds these designs, what it would
cost to interoperate, and exactly how far we are allowed to phrase each claim
without overclaiming.

## Source truth

- **HELM receipt format**: `protocols/specs/rfc/receipt-format-v1.md` (v1.0.0,
  Final). Every HELM cell below is bound to a section of that spec — no HELM
  capability is asserted here that the spec does not normatively define. Golden
  vectors live in `tests/conformance/` and `core/pkg/contracts/testdata/`.
- **AAR / Pipelock** and **IETF ACTA** columns describe those external designs
  at the level needed for the comparison. They are *their* claims, not HELM
  measurements, and are not reproduced from a HELM-controlled artifact. Treat
  them as "best current understanding of the external spec," to be re-checked
  against the upstream document before any external publication.

> [!IMPORTANT]
> This document is internal positioning, not a marketing artifact. The
> "wording guardrail" column is normative for any external copy: do not phrase a
> HELM claim more strongly than the guardrail permits.

## Why this matters

Signed agent-action receipts are converging into a category. AAR/Pipelock and
the ACTA draft both stake out "cryptographically signed, verifiable record of
what an agent was permitted to do." HELM's receipt predates neither claim of
superiority nor a finished interop story — so this page records, honestly, where
the HELM v1.0 wire format stands and what the bridge would cost.

## Primitive-by-primitive comparison

| Primitive | HELM: matches / exceeds / gap | Interop cost | Wording guardrail (no overclaim) |
| --- | --- | --- | --- |
| **Canonical serialization** | **Matches.** HELM mandates RFC 8785 JCS for content addressing (spec §4.1). AAR/Pipelock and ACTA both rely on a deterministic canonical form before signing. | Low if the peer uses JCS; medium if the peer uses a different canonicalization (e.g. JWS/JCS-of-JWS, or protobuf-canonical) — a transcoder must re-canonicalize without changing semantics. | Say "uses RFC 8785 JCS, the same canonicalization discipline as peer designs." Do **not** say "byte-compatible with ACTA/AAR" — that is unverified. |
| **Content-addressed ID** | **Matches/exceeds.** `receipt_id = SHA-256(canonical_json(receipt_without_id))` (spec §2.1, §4.2). Self-certifying ID is at least as strong as a peer that signs an externally-assigned UUID. | Low. A peer expecting a UUID can carry `receipt_id` as an opaque string; a peer expecting content addressing can recompute it. | "Content-addressed via SHA-256 over canonical JSON." Avoid "more secure than X" — it is a different ID model, not a measured improvement. |
| **Signature scheme** | **Matches.** Ed25519 over `receipt_id`, with `signer_key_id` referencing a published trust root (spec §2.3). | Low–medium. If a peer mandates JWS/COSE envelopes or a different curve (ECDSA P-256), a wrapping/translation layer is required; the signed preimage differs. | "Ed25519-signed, offline-verifiable." Do **not** claim JWS/COSE compatibility — HELM signs a bare preimage, not a JOSE/COSE structure. |
| **Verdict semantics** | **Exceeds (richer).** Three-valued `ALLOW \| DENY \| ESCALATE` (spec §2.2), where ESCALATE encodes human-in-the-loop. A binary allow/deny peer cannot represent ESCALATE losslessly. | Medium. Mapping ESCALATE onto a binary peer loses information; the safe mapping is ESCALATE → deny-pending, never ESCALATE → allow. | "Three-valued verdict including an explicit escalate/HITL state." Do **not** say peers "lack" HITL — they may model it elsewhere; say HELM carries it *in the receipt*. |
| **Reason codes** | **Exceeds.** Normative reason-code registry of 20 codes across Policy/PDP/Resource/Schema/Temporal/Security/Tenancy/Jurisdiction (spec §2.5), required on DENY/ESCALATE. | Medium. Peers with a free-text or smaller enum need a mapping table; unmapped codes should pass through as an opaque string, not be dropped. | "Carries a normative reason-code registry." Do **not** claim the registry is an industry standard — it is HELM-defined. |
| **Causal ordering** | **Exceeds.** Monotonic `lamport` clock, strictly increasing per kernel instance (spec §2.4), plus ProofGraph hash-chained DAG (spec §3). Tamper-evident ordering, not just per-record signatures. | Medium–high. A peer with only per-record signatures (no chain) cannot consume the ordering guarantee; bridging preserves signatures but drops chain semantics unless the peer adopts the ProofGraph node reference. | "Lamport-ordered and hash-chained into a ProofGraph DAG." Do **not** imply peers are "unordered" without checking — say HELM's ordering is *in-band and verifiable offline*. |
| **Proof-graph binding** | **Exceeds / potential gap for peers.** Each receipt MUST map 1:1 to a ProofGraph node via `proofgraph_node` (spec §3, §5 step 5). This is a HELM-specific structure. | High to fully interoperate. A peer without a ProofGraph can ignore `proofgraph_node` (still verifies the receipt), but cannot reproduce the DAG-level tamper evidence. | "Binds each receipt to a tamper-evident ProofGraph node." Do **not** claim peers can verify the DAG — they verify the *receipt*; DAG verification needs the HELM ProofGraph. |
| **Counterfactual / observe-only receipts** | **Exceeds (distinctive).** `enforcement = enforced \| counterfactual`, with counterfactual receipts binding `observe_grant_id` + sealed boundary record, carrying `would_have_verdict`, and signed over an enforcement-prefixed preimage so they can never be replayed as enforced (spec §2.6). | High. Most peers have no notion of a no-authority "would-have" receipt; a bridge MUST NOT present a counterfactual receipt to a peer that would read it as enforced. Default-safe mapping: drop or clearly relabel. | "Distinguishes enforced vs counterfactual receipts cryptographically." This is a genuine differentiator — but phrase it as "we found no equivalent in the reviewed peer specs," not "no other receipt format has this." |
| **Offline verification** | **Matches.** Verifiable with only JCS + SHA-256 + Ed25519, by parties who do not trust the producer (spec §Implementation Independence, §5). | Low. This is the shared premise of all three designs; interop here is about key distribution, not format. | "Offline-verifiable by untrusting third parties using open primitives." Safe to state plainly — it is normative in the spec. |
| **Payload binding** | **Matches.** `payload_hash` = SHA-256 of the execution payload (spec §2). Receipt commits to the effect without embedding it. | Low. A peer carrying an inline payload vs a hash needs a content-resolution step, but the commitment model is standard. | "Commits to the execution payload by hash." Do **not** claim the payload itself is portable — only its hash is in the receipt. |
| **Fail-closed semantics** | **Matches.** No valid receipt ⇒ no effect execution (spec §6). | N/A (deployment property, not wire-format). Does not affect on-the-wire interop. | "Fail-closed: no receipt, no execution." Spec-backed; safe to state. Keep it a property of the *kernel*, not of the receipt bytes. |

## Net read

- **No on-the-wire format gap that blocks interop.** HELM's primitives are the
  shared category primitives (JCS, SHA-256, Ed25519, content addressing,
  offline verification). The real interop cost is in translation layers
  (signature envelope shape, verdict/reason mapping), not in missing
  capabilities.
- **HELM's distinctive surface is structural, not cryptographic:** ProofGraph
  binding and counterfactual receipts. These are where HELM exceeds the reviewed
  peer designs — and also where a naive bridge can silently drop guarantees, so
  they need the strictest wording guardrails.

## Honest gaps / follow-ups

1. **External specs not pinned in-repo.** The AAR/Pipelock and ACTA columns are
   based on the external designs as understood at review time, not on a vendored
   copy of `draft-farley-acta-signed-receipts-01` or an AAR/Pipelock spec
   artifact. Before any external publication, re-verify each peer cell against
   the upstream document and pin the exact draft revision.
2. **No conformance bridge exists yet.** There is no HELM↔ACTA or HELM↔AAR
   transcoder or golden cross-vector in this repo. Until one lands under
   `tests/conformance/`, do not claim "interoperates with" — claim only
   "shares the underlying primitives with."
3. **Counterfactual uniqueness is scoped to the reviewed specs.** The claim that
   no peer has an enforced/counterfactual distinction is bounded by what was
   reviewed here; it is not a survey of the whole field.
