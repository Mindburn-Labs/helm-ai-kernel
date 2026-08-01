# ADR 0002: Store the Canonical Receipt Envelope

<!-- quantum_posture: this decision concerns serialization and storage of receipt
bytes. It is orthogonal to signature algorithm choice and makes no post-quantum
claim; the Ed25519/ML-DSA profile selection is unaffected. -->

Status: Proposed
Date: 2026-07-26

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

## Decision

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

## Alternatives considered

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

## Consequences

- Closes F-05, F-06, F-19, F-20 and F-23 with one change, because all five are
  the same root cause.
- Storage grows by roughly 1–4 KB per receipt, duplicating data already present
  in the indexed columns. Cheap relative to what it buys.
- Existing receipts have no stored envelope. `crypto.VerifyReceiptSignature`
  already reports which preimage matched, so legacy rows verify under v4 and are
  reported as deprecated rather than failing. No backfill is required for
  correctness; a backfill would only upgrade their integrity claim.
- The indexed columns become derived data. A future change must treat the stored
  bytes as the record and the columns as a cache, or the two can drift again.
- Producers other than the store — mcp-proof, demo, launchpad — must emit the
  same canonical bytes, which is what makes F-19 and F-20 resolvable rather than
  merely documented.

## Open question for the product owner

Whether receipts are expected to be reconstructable from the store at all, or
whether the EvidencePack is the system of record and the store is an index. This
decision assumes the former, because the store currently builds the receipt
chain and therefore cannot be a mere index. If the intent is the latter, the
chain construction has to move out of the store first, and that is a larger
change than this one.
