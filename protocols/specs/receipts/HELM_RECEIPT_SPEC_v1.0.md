# HELM Receipt Spec v1.0 (draft)

Status: **draft** · Scope: external decision-receipt interoperability + classification.

## 0. Why this exists

Signed, offline-verifiable agent-action receipts are no longer a unique idea — AAR
(Pipelock), the IETF `draft-farley-acta-signed-receipts` (ACTA), Signet, and others
already use the same primitives HELM uses (Ed25519 + RFC 8785 JCS + SHA-256). So
HELM does **not** claim to have "the only" or "the first" receipts.

What HELM does claim, and this spec makes precise:

> **HELM verifies AAR, ACTA, and HELM receipts. HELM-native receipts add a
> verdict-bound effect permit and a compliance-mapped EvidencePack for *admissible
> execution proof*. External decision receipts are *decision-level proof* only.**

The defensible position is neutrality + binding: HELM is a verifier neutral enough
that an auditor, insurer, or counterparty can check a receipt **without trusting the
producing vendor**, and HELM-native receipts bind a fail-closed policy *verdict* to
the *effect* that was permitted.

## 1. Taxonomy (`kind`)

Every receipt HELM reasons about carries a top-level `kind` discriminator:

| `kind` | Meaning | Proof level |
| --- | --- | --- |
| `helm_native_receipt` | Binds a HELM policy verdict → effect permit → signed receipt → EvidencePack. | **Execution proof** |
| `external_decision_receipt` | Third-party decision receipt (AAR, ACTA). | Decision-level proof |
| `external_scan_receipt` | Third-party scan/proxy receipt (e.g. Pipelock egress). | Observation-level proof |

**Hard rule:** no external-format adapter may emit `helm_native_receipt`. This is
enforced in code (`decisionreceipt.Registry.Register` panics on a `helm_native`
adapter; `VerifyBundle` rejects any external receipt that claims the native kind).

## 2. Classification ladder

Verifying an external receipt assigns a `classification`, never HELM-native authority:

| `classification` | Condition |
| --- | --- |
| `crypto_conformant` | Signature verifies against an **externally trusted** key; chain (if any) links; content hash matches. Decision-level proof. |
| `crypto_compatible_non_conformant` | Cryptographically well-formed and the signature verifies, but only against a key **disclosed inside the bundle** (self-consistency, not authenticity), or a HELM binding is absent. |
| `unverified` | No trusted key, invalid signature, or content-hash mismatch. |

A bundle's classification is the **weakest** of its receipts. A receipt verified
only against a bundle-disclosed key is capped at `crypto_compatible_non_conformant`
— it is never silently treated as execution proof.

## 3. Canonicalization contract

- Canonical bytes = **RFC 8785 (JCS)** over the receipt with the HELM-assigned and
  signature fields cleared: `signature`, `receipt_hash`, `classification`,
  `original_digest`, `limitations`.
- `receipt_hash` = `"sha256:" + hex(SHA-256(canonical bytes))`.
- `signature` = Ed25519 over the **same** canonical bytes; encoded hex or base64.
- Chain linkage: `prev_receipt_hash` of receipt *n* equals `receipt_hash` of *n-1*.

> **Adapter rule (the #1 correctness risk):** a format adapter's
> `CanonicalSignedBytes` must reproduce the **producer's** signing input, not HELM's
> JCS, when they differ. An adapter must not be shipped as "supported" until it is
> locked against **vendor-emitted** test vectors. (See §6.)

## 4. Normalized schema

The HELM-internal normalized representation every adapter maps into is
`contracts.ExternalDecisionReceipt` (JSON Schema:
`protocols/json-schemas/receipts/external_decision_receipt.v1.schema.json`, to be
added alongside the AAR/ACTA adapters). Bundle envelope:
`ExternalDecisionReceiptBundle` (`public_keys` are local-only and never fetched over
the network during verification).

## 5. Reference implementation

- Library: `core/pkg/verifier/decisionreceipt` — pluggable `FormatAdapter` registry +
  signature/classification verify engine, reusing `canonicalize.JCS` and Ed25519.
- Built-in adapter: `helm_external.v1` — HELM's self-describing external decision
  format, fully tested end-to-end (round-trip, classification ladder, tamper, chain,
  native-claim guard). It is the import target vendor adapters normalize into.

## 6. Roadmap (honest)

| Item | Status |
| --- | --- |
| Taxonomy + classification + verify engine + `helm_external.v1` | **this spec / shipped in code** |
| `aar.v1` adapter | pending upstream AAR test vectors |
| `acta.v1` adapter | pending IETF `draft-farley-acta-signed-receipts` test vectors + a filed position |
| `pipelock.v1` (scan) adapter | pending sample receipts |
| JSON Schemas under `protocols/json-schemas/receipts/` | with each adapter |
| `helm-ai-kernel verify aar\|acta\|pipelock` CLI + import→EvidencePack | follow-on |
| Hosted verifier (CLI-parity, offline) | follow-on |

No adapter is advertised as "supported" before it verifies real vendor receipts
against committed vectors. Until then the classification ladder makes the
uncertainty explicit rather than overclaiming.
