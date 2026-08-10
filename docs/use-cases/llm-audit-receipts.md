---
title: Signed Receipts for AI Agent Actions
last_reviewed: 2026-08-10
---

# Signed Receipts for AI Agent Actions

Logs answer "what did we write down"; receipts answer "what actually happened,
and can someone else check?" HELM AI Kernel signs every boundary decision with
Ed25519 over a JCS (RFC 8785) canonical form. **Status: Live** in HELM AI
Kernel.

The norm this enables is simple: no receipt, no production. An agent action that
cannot be replayed and verified did not happen as far as your audit trail is
concerned.

## What the signature covers

The `receipt.v5` signing envelope is a fixed 13-key JCS object
(`core/pkg/crypto/canonical.go:169-183`): `signature_version`, plus
`receipt_id`, `decision_id`, `effect_id`, `status`, `output_hash`, `prev_hash`,
`lamport_clock`, `args_hash`, `verdict`, `reason_code`, `policy_hash` and
`session_id`.

`contracts.Receipt` carries 76 JSON fields
(`core/pkg/contracts/receipt.go:9-116`). Twelve receipt fields plus the version
tag form the signing preimage. The remaining fields are outside that preimage,
so the receipt signature alone does not authenticate them. `timestamp`,
`executor_id`, `correlation_id`, `metadata`, `key_id`, `public_key_set`,
`merkle_root`, `witness_signatures`, `model_hash`, `tool_name` and `risk_tier`
are examples; `correlation_id` says so in its own struct comment: treat it as
*a recorded claim, not signed evidence*
(`core/pkg/contracts/receipt.go:15-16`). A following receipt may detect changes
to fields included in its predecessor chain hash, subject to the exclusions
below.

So state the guarantee precisely, because the precise version is the one worth
having: **the governance meaning of a receipt — its verdict, reason code, policy
hash, session, and the hashes binding the arguments and output — cannot be
rewritten without invalidating the signature.** Per
[ADR 0002](../adr/0002-canonical-receipt-bytes.md) (amended 2026-08-06) and
[ADR 0003 §D5](../adr/0003-normative-artifact-arbitration.md), no document may
call a HELM receipt tamper-evident without naming the fields it covers.

Two limits apply today:

- **Chaining covers backwards, not forwards.** `prev_hash` is signed and is a
  hash of the preceding receipt after `Transparency`, `LogID`, and `LeafIndex`
  are excluded. Altering another hashed field of a receipt that has a successor
  breaks the successor's chain check. Those three anchoring fields are not
  covered by the causal hash, and the final receipt has no successor to provide
  successor-chain coverage.
- **Unversioned receipts have two compatibility paths.** The standalone
  `receipt_verify` path treats a receipt with no `signature_version` as legacy
  V4: eight fields joined with `:`
  (`core/pkg/receiptverify/receiptverify.go:225-229`). The separate
  `crypto.VerifyReceiptSignature` compatibility helper first tries the
  historical whole-receipt JCS candidate and then V4
  (`core/pkg/crypto/canonical_v5.go:115-135`). The 13-key envelope applies only
  to receipts that declare `receipt.v5`.

## Verifying a receipt chain

`receipt_verify` checks receipt chains and optional EffectPermits with classical
Ed25519 only. Hybrid and post-quantum receipt profiles are unsupported. It uses
no HELM service in the trust path and opens no sockets by construction rather
than by policy: the binary's transitive import graph contains no transport
package, and a test fails the build if one appears
(`core/pkg/receiptverify/receiptverify_test.go:40-78`). **Status: Live in tagged source.** The
`v0.8.3` tag contains the command and its dedicated build target, but the
`v0.8.3` GitHub Release does not publish standalone `receipt_verify-*` assets.

For each receipt, the verifier reconstructs the preimage declared by
`signature_version` (legacy V4 when absent, `receipt.v5` when declared) and
accepts the signature if it verifies under any caller-supplied Ed25519 key. An
unknown preimage version is rejected. The receipt's `key_id` is only a key-order
hint; every supplied key is trusted, and the verifier does not bind any key to
an organization. An auditor, insurer, or counterparty must obtain the signer's
public key over an independent channel. Running with `--allow-self-attested`
uses key material carried with the input; that shows internal consistency and
nothing about origin.

The `receipt.v5` byte-construction rule is not defined by a published normative
specification. This verifier reconstructs the current implementation's preimage;
its pass shows agreement with that implementation, not conformance to a public
receipt wire specification. The mainline receipt is recorded as
integrity-UNSPECIFIED in
[ADR 0003 §D4](../adr/0003-normative-artifact-arbitration.md).
**Status: unpublished.**

## Source Truth

- [Quickstart](../QUICKSTART.md)
- [Execution security model](../EXECUTION_SECURITY_MODEL.md)
- [MCP integration](../INTEGRATIONS/mcp.md)
- [Verification](../VERIFICATION.md)
- [ADR 0002 — canonical receipt bytes](../adr/0002-canonical-receipt-bytes.md)
- [ADR 0003 — normative artifact arbitration](../adr/0003-normative-artifact-arbitration.md)
