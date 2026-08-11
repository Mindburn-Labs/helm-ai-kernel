---
title: "HELM Receipt Format Specification"
status: final
version: "1.0.0"
created: 2026-02-25
finalized: 2026-03-06
specifies: launch_effect_receipt.v1
deployment_status: preview
authors:
  - HELM Core Team
---

<!-- quantum_posture: this v1 profile uses classical Ed25519 signatures and
makes no post-quantum claim; receipt-pq-hybrid-profile-v1.md defines the
separate draft Ed25519 + ML-DSA-65 profile. -->

# RFC: HELM Receipt Format v1.0 — Launch Effect Receipt Profile

## Abstract

This document specifies the canonical format of the **Launch Effect Receipt**
(`launch_effect_receipt.v1`): a cryptographically signed, content-addressed
record that attests to a governance decision and its execution outcome for one
preview Launch Mission effect.

It is **not** a specification of every artifact HELM calls a receipt. §1.2 names
the family this document governs and the families it does not. Read §1.2 before
implementing anything here.

## Status

**Specification maturity:** Final — Normative Standard, for the
`launch_effect_receipt.v1` profile only.

**Deployment status:** **Preview**, `execution_enabled: false`
(`protocols/json-schemas/effects/launch/launch_effect_receipt.v1.json`
`x-helm.status`). The profile has no non-test emitter: outside its own
definition file, `LaunchEffectReceipt` has no consumer in the tree
(`git grep -l LaunchEffectReceipt -- '*.go'` resolves only to
`core/pkg/contracts/launch_effect_receipt.go` in production, with tests referencing
it in `core/pkg/contracts/*_test.go`). "Final" describes the contract,
not production behaviour — a conformance claim made against this document is a
claim about a contract, never about a shipping surface.

## Implementation Independence (Informative)

This format is an open specification. Independent implementations are permitted and encouraged; compatibility is a statement about wire behavior — verifiable against the reference pack at `reference_packs/launch-mission-v1/` (canonical vectors in `vectors.json`, independent stdlib-Python verifier in `verify_vectors.py`, run by `make verify-launch-mission-vectors`) — not about the use of HELM software or branding. Receipts are verifiable offline by parties that do not trust the producing implementation, using only JCS (RFC 8785), SHA-256, and Ed25519. This section is informative and introduces no normative changes to the v1.0 wire format.

> The golden vectors for this profile are in `reference_packs/launch-mission-v1/`,
> not in `tests/conformance/`. `tests/conformance/` holds no launch effect
> receipt vector.

## 1. Introduction

HELM is an AI governance kernel that produces an immutable audit trail
of every governance decision and tool execution. The receipt is the
fundamental unit of this audit trail.

### 1.1 Requirements Language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in RFC 2119.

### 1.2 Scope — which receipt this document specifies

HELM issues several receipt families. They do not share a field set, a signing
preimage, or a version tag. Building the wrong one against this document
produces an artifact that fails validation on first use, so the mapping is
stated normatively here.

| Family | Specified by this document? | Where its bytes are defined |
| --- | --- | --- |
| `launch_effect_receipt.v1` — `LaunchEffectReceipt` | **Yes** — §2 (excluding §2.6), §3, §4, §5 | this document + `protocols/json-schemas/effects/launch/launch_effect_receipt.v1.json` (which declares `x-helm.receipt_format: receipt-format-v1`) + `reference_packs/launch-mission-v1/` |
| `CounterfactualReceipt` | **Partially** — §2.6 defines its signing preimage only | §2.6 + vector at `core/pkg/contracts/testdata/counterfactual_receipt_v1.json`. Its wire shape has no schema, no protobuf message and no OpenAPI component, and is therefore unspecified. |
| `contracts.Receipt` / `receipt.v5` — the mainline kernel receipt | **No** | **No published document defines its bytes.** Its field set is `core/pkg/contracts/receipt.go`; its wire contract is `api/openapi/helm.openapi.yaml` (HTTP) and `protocols/proto/helm/kernel/v1/helm.proto` (gRPC). Third-party verifiability MUST NOT be claimed for it. |
| External decision receipt (`helm_external.v1`) | **No** | `protocols/specs/receipts/HELM_RECEIPT_SPEC_v1.0.md` |

The mainline receipt is the one an integrator is most likely to meet first, and
it is the family this document does **not** specify. It carries different JSON
names for the concepts §2 lists — `status`, `tool_name`, `lamport_clock`,
`key_id`, `blob_hash`/`output_hash`, `prev_hash` — and it has no
`receipt_version`, `principal`, `proofgraph_node`, `signer_key_id` or
`payload_hash` field at all. Do not read §2 as a description of it, and do not
"correct" §2 toward it: the two are different artifacts, and this profile is
vector-pinned and CI-verified.

The per-family arbitration rules, including what an implementer does when
representations disagree, are recorded in
`docs/adr/0003-normative-artifact-arbitration.md`. That ADR is a decision
record, not a normative source for bytes.

## 2. Receipt Structure

A receipt MUST be a JSON object. The fields below are the profile's governance
core — the ones every citation of this format refers to:

```json
{
  "receipt_version": "1.0",
  "receipt_id": "<content-addressed SHA-256 hash, lowercase hex, unprefixed>",
  "decision_id": "<decision identifier>",
  "effect_id": "<effect identifier>",
  "verdict": "ALLOW",
  "principal": "<principal identifier>",
  "tool": "<tool identifier>",
  "action": "<action description>",
  "timestamp": "<RFC 3339 timestamp>",
  "lamport": <monotonic Lamport clock>,
  "proofgraph_node": "sha256:<64 lowercase hex>",
  "signature": "<Ed25519 signature, base64>",
  "signer_key_id": "<public key identifier>",
  "payload_hash": "sha256:<64 lowercase hex>",
  "metadata": { "profile": "launch_effect_receipt.v1", "redaction_profile_hash": "sha256:<64 lowercase hex>" }
}
```

**This excerpt is not a complete receipt, and a receipt built from it alone will
be rejected.** The profile's complete field set is normative in
`protocols/json-schemas/effects/launch/launch_effect_receipt.v1.json`, which
sets `additionalProperties: false` and lists **62 required properties** — the
fifteen above plus `schema_version`, `kind`, `receipt_chain_id`,
`receipt_revision`, `reconciliation_revision`, `audience`,
`kernel_trust_root_id`, the tenancy and mission identifiers, the input/plan/
request/args/result hashes, the approval, dispatch-admission, reservation and
permit bindings with their hashes, `policy_epoch`, `emergency_fence_epoch`, the
connector authority bindings, the reconciliation and dependency fields, and
`signature`. Implementers MUST build against the schema and validate against the
reference-pack vector at `reference_packs/launch-mission-v1/vectors.json`
(`receipt.value`, an 82-field object), not against this excerpt.

Three of those bindings are checked as invariants rather than as field presence,
and an otherwise schema-valid receipt is rejected without them
(`core/pkg/contracts/launch_effect_receipt.go` `ValidateLaunchEffectReceiptSemantics`):

- `payload_hash` MUST equal `request_hash`;
- `decision_id` MUST equal `kernel_verdict_ref`;
- `schema_version` MUST be `launch_effect_receipt.v1`, `receipt_version` MUST be
  `1.0`, and `kind` MUST be `helm_native_receipt`.

### 2.1 Receipt ID

The `receipt_id` MUST be computed over the receipt with **both** `receipt_id`
and `signature` set to the empty string — not merely with `receipt_id` removed.
Clearing `signature` is what breaks the otherwise circular dependency between
the content address and the signature over it; a verifier that skips it derives
a different digest and rejects every valid receipt.

```
receipt_id = lowercase_hex( SHA-256( JCS( receipt with receipt_id="" and signature="" ) ) )
```

`JCS` is RFC 8785 JSON Canonicalization. The result is 64 lowercase hexadecimal
characters with no `sha256:` prefix — unlike `proofgraph_node` and
`payload_hash`, which carry the prefix.

This is the projection both implementations perform: `LaunchEffectReceiptSigningBytes`
in `core/pkg/contracts/launch_effect_receipt.go`, and the independent verifier
at `reference_packs/launch-mission-v1/verify_vectors.py` (`verify_receipt`),
which is the artifact that makes the rule falsifiable without reading HELM's Go.

### 2.2 Verdict

The `verdict` field carries the governance decision. The general HELM verdict
domain is:

- `ALLOW` — The decision was permitted.
- `DENY` — The decision was denied.
- `ESCALATE` — The decision requires human review.

**In this profile `verdict` MUST be `ALLOW`.** The schema pins it to
`{"const": "ALLOW"}` and the implementation rejects any other value: a launch
effect receipt exists only to attest a permitted, dispatched effect, and its
`decision_id` MUST equal the `kernel_verdict_ref` of that ALLOW decision. A
denied or escalated launch effect produces no receipt in this profile. `DENY`
and `ESCALATE` remain valid verdict values elsewhere in HELM; they are not
constructible here.

### 2.3 Signature

The `signature` field MUST be an Ed25519 signature over the `receipt_id`.
Precisely: the signed message is the **ASCII bytes of the 64-character lowercase
hexadecimal `receipt_id` string** — the hex text, not the 32 bytes it decodes
to — and the signature is encoded as standard base64 (88 characters ending in
`==` for a 64-byte signature).

The `signer_key_id` MUST reference a key published in the trust root. A verifier
MUST resolve it through the trust root and MUST NOT accept a public key carried
by the receipt it is verifying.

### 2.5 Reason Code

> **Not a field of this profile.** The launch effect receipt schema sets
> `additionalProperties: false` and defines no `reason_code` property, so a
> conforming `launch_effect_receipt.v1` can never carry one — consistent with
> §2.2, where the only permitted verdict is `ALLOW`. This registry is reproduced
> here because §2.6 and other HELM receipt families reference it.
>
> **The canonical registry is `protocols/specs/rfc/reason-codes-v1.md`**, which
> defines 33 codes. The 21 below are a subset of it, retained for the citations
> in this document; they are not the complete vocabulary. Implementers MUST read
> the registry spec, and `contracts.IsCanonicalReasonCode`
> (`core/pkg/contracts/verdict.go`) is the acceptance test.

Where a receipt family admits a `reason_code` and its `verdict` is `DENY` or
`ESCALATE`, that field SHOULD be present. Codes cited by this document:

| Code                     | Category     | Description                                       |
| ------------------------ | ------------ | ------------------------------------------------- |
| `POLICY_VIOLATION`       | Policy       | General policy rule violation                     |
| `NO_POLICY_DEFINED`      | Policy       | No policy exists for the requested action         |
| `POLICY_NOT_READY`       | Policy       | No verified policy snapshot is installed          |
| `POLICY_HASH_MISMATCH`   | Policy       | Policy bytes failed expected hash verification    |
| `POLICY_SIGNATURE_INVALID` | Policy     | Policy signature or provenance verification failed |
| `POLICY_EPOCH_CHANGED`   | Policy       | Policy epoch changed before intent issue          |
| `PRG_EVALUATION_ERROR`   | Policy       | Error evaluating the Proof Requirement Graph      |
| `MISSING_REQUIREMENT`    | Policy       | Required evidence or condition not met            |
| `PDP_DENY`               | PDP          | External policy decision point denied the request |
| `PDP_ERROR`              | PDP          | External PDP returned an error (fail-closed)      |
| `BUDGET_EXCEEDED`        | Resource     | Financial or rate budget exhausted                |
| `BUDGET_ERROR`           | Resource     | Error checking budget (fail-closed)               |
| `ENVELOPE_INVALID`       | Schema       | Effect envelope failed structural validation      |
| `SCHEMA_VIOLATION`       | Schema       | Payload violates declared schema                  |
| `TEMPORAL_INTERVENTION`  | Temporal     | Temporal guardian triggered intervention          |
| `TEMPORAL_THROTTLE`      | Temporal     | Temporal guardian applied throttling              |
| `SANDBOX_VIOLATION`      | Security     | Sandbox security boundary violated                |
| `PROVENANCE_FAILURE`     | Security     | Artifact provenance verification failed           |
| `VERIFICATION_FAILURE`   | Security     | Cryptographic verification failed                 |
| `TENANT_ISOLATION`       | Tenancy      | Multi-tenant isolation boundary violated          |
| `JURISDICTION_VIOLATION` | Jurisdiction | Jurisdictional constraint not met                 |

### 2.4 Lamport Clock

The `lamport` field MUST be an unsigned integer. An emitter conforming to this
profile MUST assign a value strictly greater than every receipt it previously
issued from the same HELM kernel instance. A standalone receipt cannot prove
that instance-wide history; verification can enforce only the source-owned
minimum and the predecessor/revision ordering supplied with the receipt.

`lamport` MUST be at least 1 and MUST NOT exceed 9007199254740991 (2^53 − 1).
The upper bound is normative, not advisory: JCS serializes numbers through the
IEEE 754 double range, so a larger value could not be canonicalized identically
by every conforming implementation. The same bound applies to `effect_ordinal`,
`emergency_fence_epoch`, `receipt_revision` and `reconciliation_revision`.

### 2.6 Enforcement and Counterfactual Receipts

> **Scope.** This section specifies the signing preimage of the
> `CounterfactualReceipt` family (`core/pkg/contracts/counterfactual_receipt.go`),
> not the launch effect receipt of §2.1–§2.5. A counterfactual receipt's **wire
> shape is unspecified** — it has no JSON Schema, no protobuf message and no
> OpenAPI component — so the preimage rule below, the invariants below, and the
> vector at `core/pkg/contracts/testdata/counterfactual_receipt_v1.json` are the
> normative statements this document makes about it. `launch_effect_receipt.v1`
> defines no `enforcement` property and cannot carry one.

A CounterfactualReceipt MUST carry `enforcement = counterfactual`; the field MUST
NOT be omitted, and `enforced` is forbidden for this receipt family.
`counterfactual` means the verdict is the one the PDP **would** have issued under
an explicit, time-boxed observe grant. The recorded verdict is not enforced,
but the separate grant may still let shadow mode dispatch the evaluated action
and produce real effects; this receipt does not authorize that dispatch.

A counterfactual receipt is signed, content-addressed, and verifiable exactly
like any other receipt, but it confers **no execution authority**. It MUST be
machine-distinct from an enforced receipt and MUST NOT be presentable or
parseable as enforced. Conflating the two is false execution authority and is
forbidden.

A counterfactual receipt MUST:

- carry `enforcement = counterfactual` (never `enforced`, never empty);
- bind the `observe_grant_id` it was produced under — no grant, no
  counterfactual receipt;
- bind the sealed boundary record (`boundary_record_id`,
  `boundary_record_hash`) whose verdict it mirrors, so an offline verifier can
  re-derive the would-have decision;
- carry the full `would_have_verdict` (`ALLOW | DENY | ESCALATE`) and, for
  `DENY`/`ESCALATE`, a canonical `reason_code`.

The signature over a counterfactual receipt MUST cover an enforcement-prefixed
preimage (`"counterfactual:" + receipt_hash`) so a signature minted over a
counterfactual receipt can never be replayed onto an enforced one. Golden
vectors for this profile live in
`core/pkg/contracts/testdata/counterfactual_receipt_v1.json`; the negative
vector (coercion to `enforced` MUST fail) is the acceptance gate.

## 3. ProofGraph Integration

Each receipt MUST correspond to exactly one node in the ProofGraph.
The `proofgraph_node` field contains the hash of the ProofGraph node,
formatted as `sha256:` followed by 64 lowercase hexadecimal characters.

ProofGraph nodes form a hash-chained DAG where each node references
its parent nodes, creating a tamper-evident audit trail.

The evidence DAG a receipt binds MUST be resolvable **without** the receipt: its
`artifact_refs` MUST NOT contain a receipt or EvidencePack reference. Evidence
precedes the receipt that cites it, and a verifier that accepts a cycle here
accepts a receipt that vouches for itself.

## 4. Serialization

### 4.1 Canonical JSON

For content addressing, receipts MUST be serialized using canonical
JSON (RFC 8785 — JSON Canonicalization Scheme).

### 4.2 Content Addressing

All content-addressed identifiers in HELM use SHA-256:

```
id = hex(SHA-256(canonical_bytes))
```

## 5. Verification

### 5.1 Content addressing and signature

1. Recompute `receipt_id` per §2.1 — with `receipt_id` and `signature` both set to `""`.
2. Verify `receipt_id` matches the declared value, compared in constant time.
3. Verify the Ed25519 `signature` over the ASCII bytes of `receipt_id`, using the public key resolved from the trust root by `signer_key_id` (§2.3). A key carried by the receipt MUST NOT be used.
4. Verify the `lamport` clock is within expected bounds (§2.4).
5. Verify the `proofgraph_node` exists in the ProofGraph.

### 5.2 Additional obligations for `launch_effect_receipt.v1`

Steps 1–5 establish that the bytes are intact and signed. They do **not**
establish that the receipt records authorized work, and a verifier that stops
there will accept a well-formed receipt for an effect that was never dispatched.
A conforming verifier of this profile MUST additionally:

6. Recompute `receipt_chain_id` from the immutable dispatch identity and verify it matches, so a revision cannot be re-parented onto different work.
7. Verify the invariant bindings of §2 — `payload_hash == request_hash` and `decision_id == kernel_verdict_ref`.
8. Resolve the durable effect reservation from its **source**, and verify the receipt's authority bindings against it. These MUST NOT be read back from the receipt under verification.
9. Verify the evidence DAG bound by `proofgraph_node` precedes the receipt and is acyclic (§3).
10. For a terminal receipt (`outcome` of `SUCCEEDED` or `FAILED`), walk the append-only predecessor chain and verify every revision, then verify non-circular EvidencePack closure against the verified predecessor. A terminal receipt with no verified predecessor MUST be rejected.

Signer keys MAY rotate between revisions, so cryptographic verification of each
predecessor is mandatory at verification time and cannot be inherited from the
head. The full sequence is implemented by `VerifyLaunchEffectReceipt` in
`core/pkg/contracts/launch_effect_receipt.go`. For the reference pack's single
receipt, the independent Python verifier at
`reference_packs/launch-mission-v1/verify_vectors.py` recomputes `receipt_id`
and `receipt_chain_id`, verifies the Ed25519 signature with the pack-supplied
public key, checks the payload/request and decision/verdict bindings, compares
the receipt with the pack-supplied authority binding, and validates the bound
evidence DAG's hashes, reservation bindings, ordering, acyclicity, and
non-circular artifact references. It does not resolve the signer key or durable
reservation from external sources, walk predecessor receipts, or verify
EvidencePack closure; those obligations are handled by
`VerifyLaunchEffectReceipt`, not by the Python reference-pack verifier.

## 6. Security Considerations

- **Fail-Closed Verification**: A conforming verifier rejects a receipt that
  fails content-address, trust-root, authority, evidence-DAG,
  predecessor-chain, or EvidencePack checks. This preview profile is not a live
  execution gate, and a receipt does not authorize dispatch.
- **Attributable Integrity**: Receipts are signed and content-addressed; origin
  attribution depends on source-owned trust-root and authority resolution.
- **Tamper Evidence**: Verification recomputes the receipt ID, Ed25519
  signature, evidence-DAG hashes and ordering, and predecessor/EvidencePack
  closure for the material those checks bind.
- **Secret Minimization**: Receipts exclude raw provider transcripts, session
  keys, private ephemeral material, and arbitrary metadata. This profile makes
  no forward-secrecy claim.

## 7. IANA Considerations

This document has no IANA actions.

## 8. References

- RFC 2119 — Key Words for use in RFCs
- RFC 3339 — Date and Time on the Internet
- RFC 8785 — JSON Canonicalization Scheme
- AIGP Four Tests Standard (4TS) v1.0
- HELM Unified Canonical Standard (UCS) v1.3

### 8.1 Normative companions for this profile

- `protocols/json-schemas/effects/launch/launch_effect_receipt.v1.json` — the complete field set, value domains and `additionalProperties: false` closure
- `reference_packs/launch-mission-v1/` — canonical vectors, negative mutations, and the independent Python verifier; gated by `make verify-launch-mission-vectors`
- `protocols/specs/rfc/reason-codes-v1.md` — the canonical reason code registry (§2.5)
- `protocols/specs/rfc/canonical-json-v1.md` — the JCS profile used for content addressing

### 8.2 Related, non-normative for this profile

- `docs/adr/0003-normative-artifact-arbitration.md` — per-family arbitration; a decision record, never a source of bytes
- `protocols/specs/rfc/receipt-pq-hybrid-profile-v1.md` — draft post-quantum hybrid profile
- `protocols/specs/rfc/receipt-transparency-v1.md` — draft RFC 6962 transparency anchoring
