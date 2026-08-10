# ADR 0003: Normative Artifact Arbitration

<!-- quantum_posture: this decision assigns normative authority between existing
representations of already-defined artifacts. It introduces no cryptographic
primitive, no key handling, and no signature algorithm, and makes no
post-quantum claim; the Ed25519/ML-DSA profile selection is unaffected. -->

Status: Accepted
Date: 2026-08-06

## Context

Every governed HELM artifact — receipt, permit, decision, evidence pack — exists
in up to five representations:

| Representation | Location |
| --- | --- |
| JSON Schema | `protocols/json-schemas/**` |
| Go struct / signing envelope | `core/pkg/contracts/**`, `core/pkg/crypto/**` |
| Protobuf message | `protocols/proto/**` |
| OpenAPI component | `api/openapi/helm.openapi.yaml` |
| Prose RFC / spec | `protocols/specs/**`, `protocols/spec/**` |

No document states which of these wins when they disagree, and they do disagree.
`protocols/json-schemas/SCHEMA_INDEX.md:3` calls itself "Normative index of all
JSON schemas" and assigns conformance levels, but a level is not an arbitration
rule: it says a schema is required, not that the schema is right when the code
says otherwise.

The cost is not theoretical. Two independent audit domains produced remediation
plans that would have edited the wrong artifact:

- One planned to add the missing signed fields to
  `protocols/json-schemas/receipt/v2.json`. Those fields are already published —
  `api/openapi/helm.openapi.yaml:4178-4224` carries all twelve plus
  `signature_version` and `signature`, and
  `protocols/proto/helm/kernel/v1/helm.proto:126-155` carries twelve of them.
  What is unpublished is the *construction rule*, which no schema can express.
- One planned to rewrite `protocols/specs/rfc/receipt-format-v1.md` §2.3 to match
  `core/pkg/crypto/canonical.go`. That RFC is correct — for
  `LaunchEffectReceipt` (`core/pkg/contracts/launch_effect_receipt.go:370-381`),
  a different receipt family. Rewriting it would have broken a vector-pinned,
  CI-verified profile in order to describe an unrelated one.

Both mistakes have the same shape: an artifact was treated as *the* definition of
a thing without asking which contract it defines and for which family.

### The conflation this ADR removes

The repository treats "the receipt schema" as one question. It is two:

- The **integrity contract** — which bytes are hashed and signed, in what
  canonicalization, in what encoding, under which version tag. This is what an
  independent verifier must reproduce byte-for-byte.
- The **wire contract** — which fields travel, what values are legal, and what
  counts as a backward-compatible change. This is what a client must parse.

An artifact can have a normative source for one and none for the other, and in
HELM today several do. Naming a single "normative representation" per artifact
is precisely what produced the two wrong plans above, because the
field-inventory answer and the byte-construction answer live in different files.

## Decision

### D1 — Every artifact family has two contracts, arbitrated separately

No document, gate, or claim may refer to "the normative representation" of an
artifact without naming which of the two contracts it means.

### D2 — Normative source per contract

**Integrity contract.** The normative source is a **preimage specification under
`protocols/specs/` together with its reference pack under
`reference_packs/<family>/`**, where the pack ships canonical bytes
(`*.c14n.json`), the signing payload, the public key, the signature, and named
negative mutations with expected errors, and where both a Go test of the form
`Test<X>ReferencePackMatchesGoImplementation` and an independent Python verifier
run from `make verify-fixtures` (`Makefile:123`, CI `.github/workflows/ci.yml:167`).

On conflict, **the specification and its pack win; the Go implementation is the
bug.** This is not a stylistic preference. If Go won, an independent
implementation built from the published spec could be declared non-conformant by
changing our Go, and the promise that a third party can verify HELM receipts
without our source would be void.

Derived and *never* normative for the integrity contract: the Go signing
envelope, JSON Schemas, protobuf messages, OpenAPI components, ADRs, and prose
anywhere else. They carry the field inventory. None of them can express key
ordering, empty-versus-absent, number formatting, timestamp normalization, or
slice-order significance — the parts an independent verifier actually gets wrong.

**Wire contract.** The normative source is `api/openapi/helm.openapi.yaml` for
HTTP surfaces and `protocols/proto/**` for gRPC surfaces. Derived: the five SDK
bindings, the JSON Schemas, and the Go structs.

OpenAPI outranks the JSON Schemas here on evidence, not convention: for the
mainline receipt it is the only representation that is field-complete for the
signed set (`api/openapi/helm.openapi.yaml:4178-4224`, whose own comment at
:4187 states the purpose — "so a verifier can reconstruct the signed governance
view"), and it is the only one behind a backward-compatibility gate
(`make openapi-breaking` → `oasdiff`, `Makefile:183`,
`scripts/ci/quality-gates.json:563-573`, run by `make quality-pr` at
`.github/workflows/ci.yml:75`).

**JSON Schemas under `protocols/json-schemas/` are derived validation views.**
They are never the integrity contract and never the source of the field set.
They MAY be normative for the *value domain* of a field — enums, formats,
constraints — when `SCHEMA_INDEX.md` says so **and** the field exists in the
wire-normative source. A schema that constrains a field the wire-normative
source does not carry is stale by definition.

### D3 — Three states, not two

A binary normative/derived split cannot describe HELM today, because for several
artifacts the published document contradicts the shipped bytes. Declaring such a
document normative would make every artifact we have ever issued non-conformant
by our own rule. Each family's integrity contract is therefore in exactly one of
three states:

1. **SPECIFIED** — a named published document plus a CI-bound reference pack
   define the bytes. The spec wins on conflict. Third-party verifiability may be
   claimed, subject to D7.
2. **UNSPECIFIED** — no published document defines the bytes. The Go signing
   envelope is the *implementation of record* and is explicitly **not** a
   specification. No document may be cited as one. The artifact carries a status
   label. Third-party verifiability MUST NOT be claimed for it.
3. **CONTRADICTED** — a published document claims to define the bytes and does
   not match what ships. **Neither side wins.** The document must be corrected or
   profile-scoped before it may be cited, and implementers must not build against
   it. A CONTRADICTED artifact must not be offered as a conformance target and
   must not appear in public copy.

### D4 — The per-family register

This is the arbitration answer. Every row was originally audited at
`origin/main` e24e90d70 and is updated when its normative source and gates land.

#### Receipts

| Family | Integrity state | Integrity source (or implementation of record) | Wire source | Derived |
| --- | --- | --- | --- | --- |
| `contracts.Receipt` / `receipt.v5` — the mainline kernel receipt | **UNSPECIFIED** | Implementation of record: `core/pkg/crypto/canonical.go:171-185` (13-key JCS envelope) reached through `ReceiptSigningPayload` (`canonical.go:217-223`); lowercase hex signature (`core/pkg/crypto/signer.go:145-148`). **No published artifact states the construction rule.** | `api/openapi/helm.openapi.yaml:4178-4224` (HTTP); `protocols/proto/helm/kernel/v1/helm.proto:126-155` (gRPC) | `protocols/json-schemas/receipt/v2.json`; the five SDK bindings; `core/pkg/contracts/receipt.go` |
| `LaunchEffectReceipt` — the Receipt Format v1 launch profile | **SPECIFIED** | `protocols/specs/rfc/receipt-format-v1.md` §2 + `protocols/json-schemas/effects/launch/launch_effect_receipt.v1.json:304-313` + `reference_packs/launch-mission-v1/` | same schema | `core/pkg/contracts/launch_effect_receipt.go` |
| `CounterfactualReceipt` | **SPECIFIED for the preimage; UNSPECIFIED for the wire shape** | `protocols/specs/rfc/receipt-format-v1.md:148-150` states the preimage `"counterfactual:" + receipt_hash`; `core/pkg/contracts/counterfactual_receipt.go:146-148` matches it exactly; vector at `core/pkg/contracts/testdata/counterfactual_receipt_v1.json` | none — no schema, no proto, no OpenAPI component | — |
| External decision receipt (`helm_external.v1`) | **SPECIFIED** | `protocols/specs/receipts/HELM_RECEIPT_SPEC_v1.0.md` §3, matching `core/pkg/verifier/decisionreceipt/helm_external.go:74-85` field-for-field | same | — |

`receipt-format-v1.md` is normative **for the launch profile only**. Its header
does not say so, which is what produced the second wrong plan; fixing the header
is P2-7. Until it says so, no surface may cite it as "the HELM receipt standard".

#### Permits

| Family | Integrity state | Integrity source (or implementation of record) | Wire source | Derived |
| --- | --- | --- | --- | --- |
| `effects.EffectPermit` / `effect_permit.v1` | **SPECIFIED** | `protocols/specs/effects/effect-permit-v1.md` + `reference_packs/effect-permit-v1/`, with Go parity and an independent Python verifier bound into `make verify-fixtures` | `protocols/proto/helm/effects/v1/effects.proto:29-50`, including the signed `evidence_bindings` at field 16; `core/pkg/crypto/permit_cross_process_test.go` proves a field-complete wire round trip | the five SDK bindings |

The integrity contract and wire field set are specified and sufficient to
reconstruct the signed preimage across a protobuf hop. This does not claim a
shipping cross-process dispatch: production still has no
`effects.EffectPermit`-to-generated-protobuf converter or Go-to-proto permit
hop. Per D7, runtime deployment remains separate from contract status.

#### Decisions

| Family | Integrity state | Integrity source (or implementation of record) | Wire source | Derived |
| --- | --- | --- | --- | --- |
| `contracts.DecisionRecord` / `decision_record.v4` | **UNSPECIFIED** | Implementation of record: `core/pkg/crypto/canonical.go:377-438` (13 keys, hand-serialized in JCS key order, version constant `contracts.DecisionRecordSignatureV4` at `core/pkg/contracts/decision.go:174`) | `api/openapi/helm.openapi.yaml:4632`; `protocols/proto/helm/kernel/v1/helm.proto` | `protocols/json-schemas/policy/policy_decision.schema.json`; SDK bindings |
| `contracts.AuthorizedExecutionIntent` / `authorized_execution_intent.v2` | **UNSPECIFIED** | Implementation of record: `core/pkg/crypto/canonical.go:88-122`, constant at `core/pkg/contracts/decision.go:159` | — | — |

The decision family is nonetheless the repository's **best existing example of
D5**: three widenings produced three distinct constants — `decision_record.v2`
(`decision.go:163`), `.v3` (:168), `.v4` (:174) — rather than one constant whose
meaning changed. The intent family is the best existing example of D6's strict
dispatch: `canonical.go:92-93` rejects an intent whose version is not exactly
`authorized_execution_intent.v2`, instead of guessing.

#### Evidence packs

| Family | Integrity state | Detail |
| --- | --- | --- |
| EvidencePack | **CONTRADICTED** | `protocols/spec/evidence-pack-v1.md` is `status: draft` in its front matter (:3) and "Draft -- Normative Standard" in its body (:26). At :207 it requires each receipt entry's `signature` to be a base64 Ed25519 signature; the kernel emits lowercase hex (`core/pkg/crypto/signer.go:145-148`) and `crypto.Verify` hard-errors on anything that is not hex (`signer.go:167-175`). At :187 it defers the receipt signature to "the receipt signing payload", a term the document never defines and which — per the receipt row above — is unpublished. Separately, the L1-normative `protocols/json-schemas/core/evidence_pack.schema.json` (`SCHEMA_INDEX.md:28`) has exactly one non-documentation mention anywhere in the tree: a `// Schema:` comment attached to a *different* type, `sovereignty.DecisionRecord`, at `core/pkg/kernel/sovereignty/types.go:10` — and `git grep 'kernel/sovereignty' -- '*.go'`, excluding tests, returns nothing, so that package has no importer either. The shipped pack manifest is a different shape entirely: `core/pkg/evidencepack/manifest.go:23-38`. |

Consequence of CONTRADICTED: `evidence-pack-v1.md` may not be cited as the
EvidencePack specification, and `evidence_pack.schema.json` may not be cited as
the EvidencePack schema, until P2-7 corrects them.

#### The families that already work — the model to copy

The reference packs below are integrity-SPECIFIED and CI-bound, each with a Go
parity test and an independent stdlib-Python verifier reached from
`make verify-fixtures` (`Makefile:123-138`, CI `.github/workflows/ci.yml:167`):

| Pack | Gate |
| --- | --- |
| `reference_packs/extauthz/` | `Makefile:136`, plus `Makefile:125-126` |
| `reference_packs/approval/` | `Makefile:127`, `Makefile:52-53`, `Makefile:137` |
| `reference_packs/approval-consumption-v1/` | `Makefile:54`, `Makefile:57` |
| `reference_packs/approval-dispatch-admission-v1/` | `Makefile:55`, `Makefile:58` |
| `reference_packs/generated-spec-approval-ceremony-v1/` | `Makefile:61-63` |
| `reference_packs/connector-release-authority-v1/` | `Makefile:65-67` |
| `reference_packs/effect-close-v1/` | `Makefile:69-71` |
| `reference_packs/effect-disposition-v1/` | `Makefile:73-76` |
| `reference_packs/effect-permit-v1/` | `make verify-effect-permit-vectors`, included by `make verify-fixtures` |
| `reference_packs/boundary-profile-v1/` | `Makefile:78-80` |
| `reference_packs/update-bundle-v1/` | `Makefile:82-85` |
| `reference_packs/launch-mission-v1/` | `Makefile:89-91` |

`reference_packs/adversarial-policy-v1/verify_vectors.py` exists but is invoked
from no Makefile target and no workflow; its verification command lives only as
prose in `docs/documentation-coverage.csv:697`. It is therefore **not** CI-bound
and does not qualify as an integrity source under D2. `emergency_stop`,
`launchpad` and `proof_replays` ship no verifier script.

### D5 — The field-addition rule

**A new signed field means a new version constant. Never a silent widening.**

When a field is added to an artifact that carries a signature:

1. **If the field enters the signed preimage**, it is a new version. The change
   MUST include: a new version constant; a new preimage function (the old one
   stays, unmodified, so previously issued artifacts remain verifiable); a new
   branch in the verify dispatch that keeps the old constant working; new
   canonical bytes and vectors in the family's reference pack; and a negative
   vector proving that bytes built under the old rule do not validate under the
   new constant. The old constant's preimage function MUST NOT be edited.
2. **If the field does not enter the preimage**, it is an unsigned transport
   field. It MUST be added to the wire-normative source (OpenAPI or proto), and
   the specification MUST list it as unsigned. A verifier MUST NOT trust it, and
   no document may describe the artifact as tamper-evident with respect to it.
3. **Silent widening is prohibited.** Adding a field to a signing-envelope struct
   without changing the version constant invalidates every previously issued
   signature while the version tag continues to claim the old rule. Worse, when
   the new field is empty in old data the bytes may still match, so "valid"
   silently means two different things with nothing on the wire to distinguish
   them.
4. **Removing or renaming a signed field is also a new version**, by the same
   argument in the other direction.

This rule is already written, correctly, as a comment on one type —
`core/pkg/crypto/effect_permit.go:30-33`: *"If a field is added to EffectPermit
it must be added here in the same change, under a new version constant — a
partially covering signature is the defect this envelope exists to prevent."*
This ADR promotes it from a comment on one type to a repository rule.

**Corollary — the version tag must be inside the bytes and must not be
omitempty.** Every HELM signing envelope already puts `signature_version` inside
the signed payload (`canonical.go:172`, `effect_permit.go:48`,
`canonical.go:429-430`), which is correct. But the mainline receipt's wire tag is
`json:"signature_version,omitempty"` (`core/pkg/contracts/receipt.go:46`), and
the verify dispatch treats an absent version as legacy v4
(`canonical.go:233-235`) rather than rejecting it. An omittable version tag with
a permissive fallback is an unversioned downgrade path: it lets an attacker
choose the weaker preimage by deleting a field. New signed artifacts MUST NOT
mark their version tag `omitempty`, and new dispatches MUST reject a missing
version — as the intent path already does at `canonical.go:92-93`. Repairing the
receipt path is P2-3's job, not this ADR's.

### D6 — What an implementer does on disagreement

1. Identify the family and its state in the D4 register.
2. **UNSPECIFIED → stop.** There is no conformance target. Do not infer the bytes
   from the JSON Schema, the proto, the OpenAPI component or a nearby RFC: those
   carry the field inventory, never the construction rule. Report "no published
   preimage" as the finding.
3. **CONTRADICTED → stop and file.** Do not pick a winner, and do not implement
   the document.
4. **SPECIFIED, and the spec disagrees with HELM's behaviour** → the
   specification and its reference pack win. HELM has the bug; file it against
   `helm-ai-kernel`.
5. **SPECIFIED, and the spec disagrees with a JSON Schema, proto message,
   OpenAPI component or SDK binding** → the specification wins for bytes. The
   derived artifact is stale, and that is a separate, lower-severity bug.
6. **Two published documents disagree about the same family** → the one named in
   D4 wins for that family; the other is out of scope for it and must be
   corrected or profile-scoped.
7. **Never resolve a conflict by reading `core/`.** If a question about the bytes
   can only be answered from our Go, the artifact is UNSPECIFIED by definition.
   Reading the Go to settle it produces an implementation that our next refactor
   silently breaks, and it conceals the defect that should have been filed.

Rule 7 is the load-bearing one. It is what makes the register in D4 falsifiable:
any family whose bytes an outside team can only reproduce by reading `core/` is
UNSPECIFIED regardless of how much documentation surrounds it.

### D7 — Status labels are part of the arbitration

SPECIFIED describes the contract, not the deployment. `LaunchEffectReceipt` is
fully SPECIFIED and simultaneously Preview, `execution_enabled: false`
(`protocols/json-schemas/effects/launch/launch_effect_receipt.v1.json:304-306`),
with no non-test emitter. Every citation of a SPECIFIED artifact MUST carry its
status label. "Specified" never implies "shipping", and a conformance claim
about a specified-but-unemitted artifact is a claim about a contract, not about
production behaviour.

### D8 — ADRs are not specifications

`docs/adr/**` records decisions and their outcomes. An ADR is **never** a
normative source under D2 and MUST NOT be cited as one, including this ADR. ADR
0002 was read as the canonical statement of receipt bytes and describes a design
that did not ship; see the reconciliation below.

## Which derivations CI actually enforces today

Under D2 the derived representations are supposed to follow their normative
source. Here is what is actually checked, so no one reads this ADR as a
description of enforcement.

| Derivation | Gate | Enforced? |
| --- | --- | --- |
| `protocols/proto/**` → all five SDK bindings | `make codegen-check` (`Makefile:456-463`), CI `.github/workflows/ci.yml:292` | **Yes** |
| `api/openapi/helm.openapi.yaml` → the five SDK `types_gen` files | `make sdk-openapi-check` (`Makefile:108-109` → `scripts/sdk/openapi_check.sh`), CI `ci.yml:294` | **Yes** |
| `api/openapi/**` backward compatibility | `make openapi-breaking` → `oasdiff --fail-on ERR` (`Makefile:183`, `scripts/ci/contract_breaking.sh:151`), gate `openapi-breaking` in the `pr` profile (`scripts/ci/quality-gates.json:563-573`) run by `make quality-pr` (`ci.yml:75`) | **Yes**, path-scoped to `api/openapi/**` |
| OpenAPI operation set ↔ served public routes | `make docs-openapi-parity` → `TestPublicDocsOpenAPIContract` (`core/cmd/helm-ai-kernel/openapi_runtime_routes_test.go:77`) | **Yes**, for routes and operationIds — **not** for schema fields |
| Reference pack ↔ Go implementation, for the eleven packs in D4 | `make verify-fixtures` (`Makefile:123-138`), CI `ci.yml:167` — Go parity test **and** independent Python verifier per pack | **Yes** |
| `protocols/proto/**` lint and backward compatibility | **Unenforced.** `make proto-lint` runs `buf lint protocols/policy-schema` (`Makefile:177-178`) and `make proto-breaking` diffs `protocols/policy-schema` only (`scripts/ci/contract_breaking.sh:184-186`). No buf module is rooted at `protocols/proto/` (`find . -name 'buf.yaml'` returns only `protocols/policy-schema/buf.yaml`). The file holding the receipt and permit wire contracts has never been lint- or breaking-checked. | **No** |
| `go-apidiff` on `protocols/` | **Does not exist.** Repository-wide `git grep apidiff` returns nothing. `CLAUDE.md` in the workspace root asserts this gate; the assertion is false and is on P2-9's list. | **No** |
| Go struct ↔ JSON Schema | `core/pkg/contracts/schema_validation_test.go:106-129` builds a Go literal and validates it against the schema. With no `additionalProperties:false` anywhere in `receipt/v2.json`, a Go field the schema lacks passes, and a schema property no Go field produces is never exercised. The gate is green while the two disagree. | **No, structurally** |
| Signed preimage field set ↔ published schema | No gate exists. | **No** |
| Go signing envelope ↔ proto field set | No gate exists. For `effect_permit.v1` a parity test is written but unmerged (kernel PR #803). | **No** |
| JSON Schema backward compatibility | No gate exists. `make quality-pr`'s `json-schemas` gate (`scripts/ci/quality-gates.json:465-479`) runs `scripts/ci/check_json_schemas.py`, which parses each file, compiles it as a JSON Schema, and rejects duplicate `$id` — nothing about fields, Go, proto, OpenAPI or `SCHEMA_INDEX.md`. | **No** |
| `SCHEMA_INDEX.md` ↔ the filesystem | No gate exists. | **No** |
| Schema and spec file *content* pinning | `make verify-boundary` (`Makefile:465-466`, CI `ci.yml:173`) pins digests including `protocols/json-schemas/receipt/v2.json` (`tools/boundary/protected.manifest:899`), `protocols/proto/helm/kernel/v1/helm.proto` (:1011) and `protocols/specs/rfc/receipt-format-v1.md` (:1033). This detects an **unreviewed change**; it does not check that the file is derived from anything. Do not read a green `verify-boundary` as contract correctness. | **Change-detection only** |
| Docs ↔ code | `make docs-coverage` / `make docs-truth` (`Makefile:496-500`) — coverage rows and truth assertions at surface granularity, not field granularity. | **Surface level only** |

Read together: **every enforced derivation runs downward from OpenAPI or proto
into generated code. Not one gate runs upward from a specification into the
signing implementation, except for the reference packs.** That asymmetry is why
`receipt.v5` remains UNSPECIFIED and why P2-3 and P2-6 are pack-shaped rather
than schema-shaped; this EffectPermit pack moves `effect_permit.v1` to
SPECIFIED.

## Consequences

- The two wrong remediation plans in Context are now answerable without opening
  the code: `receipt/v2.json` is a derived validation view, so field-adds there
  are not a fix for an unpublished preimage; `receipt-format-v1.md` is the launch
  profile's integrity source, so rewriting it to match the mainline receipt is a
  category error.
- Two families remain UNSPECIFIED (`receipt.v5`, `decision_record.v4`). This is
  intentional and is the honest state; `effect_permit.v1` is now SPECIFIED by
  its normative document and CI-bound reference pack.
- EvidencePack is named CONTRADICTED, which blocks citing
  `evidence-pack-v1.md` on any surface until P2-7 corrects it.
- The field-addition rule applies from today, including to changes that predate
  the specs. A pull request that widens a signing envelope without a new version
  constant is now refusable by reference.
- No gate enforces this ADR. It is an editorial rule until P2-9 lands the
  schema-versus-preimage parity check and a buf module rooted at
  `protocols/proto/`. That is stated here rather than implied, because an
  unenforced rule that reads as enforced is the failure mode this ADR exists to
  correct.

## Reconciliation of ADR 0002

ADR 0002 (`docs/adr/0002-canonical-receipt-bytes.md`, 2026-07-26) was verified
against `origin/main` e24e90d70 for this ADR. Its Decision has two halves and
**neither shipped as written**:

1. *"Add one column holding the exact JCS serialization that was hashed and
   signed"* (Decision, bullet 1). What shipped is `receipt_envelope JSONB`
   (`core/pkg/store/migrations/007_add_receipt_envelope.sql:7`;
   `core/pkg/store/receipt_store.go:271,295,361`), populated by
   `durableReceiptEnvelope`, which calls **`json.Marshal(r)`** —
   `receipt_store.go:215-223`. That is neither JCS nor the bytes that were
   signed; it is a Go-default marshalling of the whole receipt. The column's
   integrity anchor is the chain hash, not the signature:
   `restoreCanonicalReceiptEnvelope` (`receipt_store.go:694-707`) accepts an
   envelope only if it reproduces the persisted `chain_hash`.
2. *"Once this lands, activate the v5 JCS signing envelope
   (`crypto.ReceiptPreimageV5`)"* (Decision, closing paragraph). That function is
   **not** what signs.
   All signing routes through `ReceiptSigningPayload` (`canonical.go:217-223`) to
   `CanonicalizeReceiptV5` (`canonical.go:192`), a narrow envelope of thirteen
   JSON keys (`canonical.go:171-185`) — the twelve durable receipt fields plus
   the version tag. `ReceiptPreimageV5` (`canonical_v5.go:32`) survives only as a
   compatibility helper for unversioned receipts, as its own doc comment now says
   at `canonical_v5.go:26-31`.

The narrow envelope is, by the code's own words, *"intentionally limited to the
receipt fields the durable stores round-trip"* (`canonical.go:163-166`) — which
is substantially the alternative ADR 0002 explicitly rejected ("Narrow the chain
hash and signature to the persisted subset… Rejected, and this is the important
rejection"). Its Decision's fourth bullet claims that `ReceiptChainHash` and the
signing preimage would operate on the same bytes; they do not — `ReceiptChainHash` (`core/pkg/contracts/receipt_hash.go:20-35`) hashes a
`receiptJSONAlias` of the whole receipt minus three transparency fields, a
different document from the thirteen-key preimage.

So ADR 0002, left at `Status: Proposed` with that Decision, is the repository's
most plausible-looking description of receipt bytes and it describes a system
that does not exist. Under D8 an ADR is not a specification, but a reader
reaching for one will find this file first.

**Resolution: ADR 0002 is amended and moved to `Status: Accepted (amended
2026-08-06)`, not superseded.** Superseding it by this ADR would be wrong —
arbitration and receipt serialization are different subjects — and superseding it
by nothing would delete the only record of why the storage change was made. The
amendment, landed in the same change as this ADR:

- rewrites the Decision to state what shipped in each half, with anchors;
- records that the rejected alternative was overruled, and the reason the code
  gives for overruling it;
- states plainly that ADR 0002 is **not** the `receipt.v5` preimage
  specification, that no such specification exists, and that P2-3 owns it;
- keeps the original Decision text visible as "what was decided", so the delta
  between decision and outcome is legible rather than erased.

## References

- Kernel standards audit register, §3(b) "What we can honestly say in a
  specification today", and remediation step P2-1.
- `docs/adr/0002-canonical-receipt-bytes.md` (amended in the same change).
- `protocols/json-schemas/SCHEMA_INDEX.md` — conformance levels; not an
  arbitration rule (see D2).
- `reference_packs/README.md` — the pack pattern D2 makes normative.
