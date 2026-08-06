# ADR 0002: Store the Canonical Receipt Envelope

<!-- quantum_posture: this decision concerns serialization and storage of receipt
bytes. It is orthogonal to signature algorithm choice and makes no post-quantum
claim; the Ed25519/ML-DSA profile selection is unaffected. -->

Status: Accepted (amended 2026-08-06)
Date: 2026-07-26
Amended: 2026-08-06

> **This ADR is not a specification.** Per
> [ADR 0003 §D8](0003-normative-artifact-arbitration.md), no ADR is a normative
> source for artifact bytes. In particular **this file does not define the
> `receipt.v5` signing preimage.** No published artifact does; the mainline
> receipt's integrity contract is UNSPECIFIED in ADR 0003 §D4, and publishing it
> is remediation step P2-3. Anyone who arrived here looking for the bytes a HELM
> receipt is signed over should stop reading and file that gap.
>
> The Decision below was written on 2026-07-26 and **neither half shipped as
> written**. Both halves are recorded, with what actually landed, in
> [What shipped](#what-shipped-amendment-2026-08-06).

## Context

A receipt has no single authoritative serialization. Three consequences follow,
and they have been filed as five separate findings that are in fact one defect.

**The receipt store persists 25 of the `Receipt` struct's 75 JSON fields**
(F-23). `receiptColumns` has no column for `verdict`, `decision_hash`,
`policy_hash`, `reason_code`, `idempotency_key`, `session_id`, `tool_name`,
`risk_tier`, `evidence`, `witness_signatures`, `provenance` and forty others. A
receipt read back from the store is not the receipt that was issued.

**The chain hash covers fields the store drops.**
`contracts.ReceiptChainHash` canonicalizes the whole struct minus its
transparency fields. Verified empirically: two receipts differing only in
`verdict`, `reason_code` and `policy_hash` produce different chain hashes. But
`buildNextCausalReceipt` computes `prev_hash` from the *reloaded* previous
receipt — the truncated one. So the chain is built over the lossy copy, while
an EvidencePack holds the full copy and computes a different hash for the same
receipt. Two records, one chain, two hashes.

**The receipt signature covers 8 fields** (F-05), joined with an unescaped `:`
so field boundaries collide (F-06). Those eight are, not coincidentally,
approximately what survives the store. The narrow signature was a consequence of
the storage schema, not a design choice.

Related: three producers chain receipts three different ways (F-19), and one of
those identities is a self-declared `hash` with no specified preimage, so it
cannot be recomputed by any verifier (F-20).

*Amendment note:* the field counts above were accurate on 2026-07-26 and are
stale. At `origin/main` e24e90d70 `contracts.Receipt` carries 76 JSON tags
(`core/pkg/contracts/receipt.go:10-115`), and `receiptColumns`
(`core/pkg/store/receipt_store.go:361`) selects 31 columns, including
`receipt_envelope` and `chain_hash`. The shape of the problem is unchanged; the
numbers are not.

## Decision (as taken, 2026-07-26)

Persist the canonical signed envelope as bytes, alongside the indexed columns.

- Add one column holding the exact JCS serialization that was hashed and signed.
- Keep the existing columns for querying and indexing. They become a projection,
  not the record.
- Signature verification and chain-hash computation both read the stored bytes.
  Neither reconstructs a receipt from columns.
- `ReceiptChainHash` and the signing preimage operate on the same bytes, so the
  store copy and the EvidencePack copy are byte-identical by construction rather
  than by convention.

Once this lands, activate the v5 JCS signing envelope
(`crypto.ReceiptPreimageV5`, already implemented and tested). It has somewhere
to live only after the storage layer can return what was signed.

## What shipped (amendment, 2026-08-06)

Verified by reading `origin/main` e24e90d70. Each bullet gives the anchor.

### Half 1 — storage: shipped, but not as JCS and not as the signed bytes

- The column landed: `receipt_envelope JSONB`
  (`core/pkg/store/migrations/007_add_receipt_envelope.sql:7`;
  `core/pkg/store/receipt_store.go:271,295`), selected by `receiptColumns`
  (`receipt_store.go:361`).
- It is populated by `durableReceiptEnvelope` (`receipt_store.go:215-223`), which
  calls **`json.Marshal(r)`** — Go's default marshalling of the whole receipt.
  It is not RFC 8785 JCS, and it is not the byte string that was signed.
- Its integrity anchor is the **chain hash, not the signature**.
  `restoreCanonicalReceiptEnvelope` (`receipt_store.go:694-707`) is the strict
  proof boundary: it returns an envelope only if `durableReceiptChainHash`
  reproduces the persisted `chain_hash`
  (`restoreReceiptEnvelopeWithIntegrity`, `receipt_store.go:716-755`). A receipt
  with no matching envelope is refused for verified evidence rather than served
  from the projection. That property is real and is what this half bought.
- So the Decision's fourth bullet — *"`ReceiptChainHash` and the signing preimage
  operate on the same bytes"* — did **not** ship. `ReceiptChainHash`
  (`core/pkg/contracts/receipt_hash.go:20-35`) hashes a `receiptJSONAlias` of the
  whole receipt minus three transparency fields. The signing preimage hashes
  thirteen keys. They are different documents over the same receipt, and the
  divergence between the hashed document and the wire document is a separate open
  defect owned by remediation step P2-4.

### Half 2 — signing: `ReceiptPreimageV5` was **not** activated

- All three signers route through `crypto.ReceiptSigningPayload`
  (`core/pkg/crypto/canonical.go:217-223`) — `signer.go:221`,
  `hybrid_signer.go:132`, `mldsa_signer.go:110`.
- `ReceiptSigningPayload` calls **`CanonicalizeReceiptV5`**
  (`canonical.go:192-211`), whose payload is `receiptV5SigningEnvelope`
  (`canonical.go:171-185`): thirteen JSON keys — `signature_version` plus the
  eight V4 causal fields plus `verdict`, `reason_code`, `policy_hash`,
  `session_id`. Twelve receipt fields out of 76.
- `crypto.ReceiptPreimageV5` (`canonical_v5.go:32`) — the function this ADR named
  — is now a compatibility helper for unversioned receipts only, and its own doc
  comment says so at `canonical_v5.go:26-31`.

### The rejected alternative was overruled, and here is the reason

The Alternatives section below rejects *"Narrow the chain hash and signature to
the persisted subset"*, calling it "the important rejection". That is
substantially what shipped, and the code states the reason in its own words at
`canonical.go:163-166`:

> *"receiptV5SigningEnvelope is intentionally limited to the receipt fields the
> durable stores round-trip. It is not the wider experimental envelope in
> canonical_v5.go: signing fields the store cannot reload would make a signed
> receipt unverifiable immediately after persistence."*

Read against this ADR's Context, the two positions are answering different
failures. This ADR's rejection assumes the storage half fully closes first, so
that a wide signature always has reloadable bytes behind it. The implementation
chose to make signing correct **independently** of whether any given store,
export path or transport round-trips every field, at the cost of coverage — the
narrow envelope verifies everywhere, unconditionally.

Two things follow, and both must be said:

1. The narrowing did **not** put `verdict`, `policy_hash` and `reason_code`
   outside the signature. Those are exactly the fields the V4→V5 change added
   (`canonical.go:187-191`; `core/pkg/contracts/receipt.go:200-207`). This ADR's
   central objection to the alternative — that the decision and its reason would
   be permanently unsigned — was answered.
2. The integrity claim **is** narrower than this ADR intended: twelve fields of
   76. `timestamp`, `executor_id`, `merkle_root`, `correlation_id`, `metadata`,
   `key_id`, `public_key_set` and `witness_signatures` are carried unsigned. No
   document may describe a HELM receipt as tamper-evident without that
   qualification. The rejection was overruled on scope, not erased.

### Status of the five findings this ADR claimed to close

- **F-05** (narrow signature) — narrowed, not closed. V5 covers twelve fields,
  including the governance-meaning ones; ~64 remain unsigned.
- **F-06** (colon-delimited preimage collisions) — closed **for versioned
  receipts**: V5 is a JCS object. Still open for receipts with no
  `signature_version`, which fall back to the V4 colon string
  (`canonical.go:233-235`) because the wire tag is `omitempty`
  (`core/pkg/contracts/receipt.go:46`). See ADR 0003 §D5 corollary.
- **F-19 / F-20 / F-23** — not re-verified for this amendment. They are not
  asserted closed here.

`docs/security/kernel-security-remediation-ledger.md` remains the ledger of
record for these; note that its own F-05/F-06 rows are internally inconsistent
about what remains, which remediation step P2-7 corrects.

## Alternatives considered (as written, 2026-07-26)

**Add the fifty missing columns.** Rejected. It fixes today's struct and not the
class: the next field added to `Receipt` falls out of the signature again
because nobody added a column for it. It is also a fifty-column migration
against a table on the hot path.

**Narrow the chain hash and signature to the persisted subset.** Rejected, and
this is the important rejection. It is cheap and needs no migration, but it
shrinks the integrity claim to 25 fields and puts `verdict`, `policy_hash` and
`reason_code` permanently outside it. Those fields *are* the decision. A product
whose claim is verifiable governed execution cannot exclude what was decided,
and why, from the thing that makes it verifiable. This alternative makes the
storage convenient and the claim weaker; the decision above makes the storage
carry the claim.

*Amendment note:* this alternative was overruled. See
[the reason](#the-rejected-alternative-was-overruled-and-here-is-the-reason).

## Consequences

- Storage grows by roughly 1–4 KB per receipt, duplicating data already present
  in the indexed columns. Cheap relative to what it buys.
- Existing receipts have no stored envelope. `crypto.VerifyReceiptSignature`
  reports which preimage matched, so legacy rows verify under v4 and are
  reported as deprecated rather than failing.
- The indexed columns are derived data. A future change must treat the stored
  bytes as the record and the columns as a cache, or the two can drift again.
- Producers other than the store — mcp-proof, demo, launchpad — must emit the
  same canonical bytes.

Added by the amendment:

- **The stored envelope is not evidence of what was signed.** It is evidence of
  what was chain-hashed. A verifier reconstructing a signature from
  `receipt_envelope` must first project it onto the thirteen-key envelope; the
  stored bytes are neither the preimage nor a canonicalization of it.
- **Nothing in this file may be quoted as the receipt.v5 wire rule.** Under ADR
  0003 §D2 the mainline receipt's integrity contract is UNSPECIFIED: the only
  definition of the bytes is Go source, which ADR 0003 §D6 rule 7 forbids as a
  conformance source. P2-3 publishes the specification and
  `reference_packs/receipt-v5/`; until then no third-party verifiability claim
  may be made for `contracts.Receipt`.

## Open question for the product owner

Whether receipts are expected to be reconstructable from the store at all, or
whether the EvidencePack is the system of record and the store is an index. This
decision assumed the former, because the store builds the receipt chain and
therefore cannot be a mere index. If the intent is the latter, the chain
construction has to move out of the store first, and that is a larger change
than this one.

*Amendment note:* still open. The strict proof boundary
(`receipt_store.go:694-707`) partially answers it in practice — the store refuses
to serve an unverifiable receipt as evidence — but the question of which artifact
is the system of record has not been decided.

## References

- [ADR 0003 — Normative Artifact Arbitration](0003-normative-artifact-arbitration.md):
  §D2 (normative source per contract), §D4 (per-family register), §D5 (field
  addition and version constants), §D8 (ADRs are not specifications).
- `docs/security/kernel-security-remediation-ledger.md` — the F-05/F-06 ledger.
