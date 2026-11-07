---
title: Signed Receipts for AI Agent Actions
last_reviewed: 2026-08-10
---

<!-- quantum_posture: classical_ed25519_only; this guide claims no hybrid or post-quantum protection. -->

# Signed Receipts for AI Agent Actions

Logs answer "what did we write down"; receipts answer "what actually happened,
and can someone else check?" The classical `contracts.Receipt / receipt.v5`
profile signs its fixed envelope with Ed25519 over a JCS (RFC 8785) canonical
form. **Status: Live** in HELM AI Kernel source. Other receipt families and
hybrid or post-quantum signatures are separate profiles.

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
(`core/pkg/receiptverify/receiptverify_test.go:40-78`). **Status: Live in tagged
source; attached to GitHub Releases as standalone assets from the first release
after `v0.11.3`.** The release workflow builds `receipt_verify` for five
platforms and attaches each build to the GitHub Release, separate from the
kernel binary, so a counterparty can check a receipt without downloading the
software that issued it: `receipt_verify-linux-amd64`,
`receipt_verify-linux-arm64`, `receipt_verify-darwin-amd64`,
`receipt_verify-darwin-arm64` and `receipt_verify-windows-amd64.exe`. Each has a
keyless `.cosign.bundle` and a line in the release `SHA256SUMS.txt`. `v0.11.3`
and earlier releases do not carry these assets; for those, build the same binary
from the tagged source with `make receipt-verify-binaries`.

Download the asset for your platform from the release, then run it with the
signer's public key, obtained from the signer through a channel other than the
receipt file:

```bash
chmod +x receipt_verify-linux-amd64
./receipt_verify-linux-amd64 --receipt chain.json --key-file signer-public-key.hex
```

Exit code `0` means the chain verified under the supplied key, `1` means
verification failed, and `2` means no verdict was reported: a missing or unknown
flag, no key supplied, a receipt file or `--key-file` that cannot be read, or a
receipt file that does not parse as a receipt, receipt array or bundle. `--json`
prints the verdict as JSON. Verify the download itself with `make verify-cosign`
as described in [Verification](../VERIFICATION.md).

For each receipt, the verifier reconstructs the preimage declared by
`signature_version` (legacy V4 when absent, `receipt.v5` when declared) and
accepts the signature if it verifies under any caller-supplied Ed25519 key. An
unknown preimage version is rejected. The receipt's `key_id` is only a key-order
hint; every supplied key is trusted, and the verifier does not bind any key to
an organization. An auditor, insurer, or counterparty must obtain the signer's
public key over an independent channel. Running with `--allow-self-attested`
uses key material carried with the input; that shows internal consistency and
nothing about origin.

The [`receipt.v5` specification](../../protocols/specs/receipts/receipt-v5.md)
together with the
[`receipt.v5` reference pack](../../reference_packs/receipt-v5/) is the final
normative integrity contract for this 13-member signing preimage. ADR 0003 §D4
registers the mainline receipt as **SPECIFIED** and pins both the source-owned
Go parity test and the independent stdlib-Python verifier. This contract is
deliberately narrower than an HTTP or gRPC wire format, a receipt chain hash,
or a legacy unversioned preimage.

The reference pack demonstrates the classical Ed25519 profile only. Its
self-declared key material is not an authority binding: a counterparty still
needs independently trusted key material. Normative source status also does
not, by itself, prove that a particular release tag or binary has been
published or deployed. **Status: Final normative standard in source.**

## Verifying gateway receipts

`helm-gateway` signs one `receipt.v5` receipt for every admission decision
(`ADMITTED`, `DENIED`, `ESCALATED`) and chains them per tenant and workspace.
Its own facts (tenant, workspace, attempt and version, state, mandate,
approver, quote, authority versions) are signed through `output_hash`: the
SHA-256 of a closed binding document, `helm.gateway.receipt-binding.v1`
([schema](../../protocols/json-schemas/gateway/receipt-binding.v1.schema.json)),
whose exact bytes the gateway keeps beside the receipt. **Status: Live in
source** ([gateway effect API](../architecture/gateway-effect-api.md),
"Reading and verifying receipts offline").

Read the gateway's public key from `GET /api/v1/receipt-keyring` on its API
listener (the kernel's keyring shape under the gateway's own label,
`gateway-receipt-keyring.v1`), export a range of a
workspace's chain with the `ExportReceiptChain` RPC (a `helm.gateway.read`
token of that workspace; at most 256 receipts per call, read up to the
chain's head, which the response names as `head_seq`), and verify the
`bundle` it returns:

```bash
curl -s https://<gateway>/api/v1/receipt-keyring \
  | jq -r '.keys[] | "\(.key_id)=\(.ed25519_public_key_hex)"'
curl -s https://<gateway>/helm.gateway.v1.EffectGatewayService/ExportReceiptChain \
  -H "Authorization: Bearer $HELM_GATEWAY_READ_TOKEN" -H 'Content-Type: application/json' \
  -d '{"workspaceId":"<workspace>","fromSeq":"1","toSeq":"256"}' | jq -r .bundle > export.json
receipt_verify --receipt export.json --key "<key_id>=<public key hex>" --require-bindings --json
```

The bundle carries each binding as `gateway_bindings` (receipt id to the base64
of the exact bytes). Besides signatures and chain linkage, `receipt_verify`
runs a `binding` check on every receipt whose binding is supplied. Each
binding's SHA-256 must be its receipt's `output_hash`, and the receipt must be
signed under receipt.v5. The binding must be the closed document its version
names, in canonical form. Its chain, sequence, attempt, version, state,
verdict, reason code, policy hash, argument digest and time must equal the
signed receipt's fields and its timestamp. A tampered binding, a binding for a
receipt that is not in the file, or a gap in the range fails verification.

Bindings are checked only when supplied, and exit 0 alone does not say a
gateway receipt's own facts were checked. `--require-bindings` makes it so: a
gateway receipt without a binding then fails verification. The JSON verdict
reports `gateway_receipts` and `bindings_checked`. For one receipt read with
`GetAttemptReceipts`, pass its binding with `--binding
<receipt_id>=binding.json`.

The binding states what the gateway recorded; the verifier cannot see the
gateway's ledger. A verified range is contiguous, but it does not show that
nothing follows it.

## Source Truth

- [Quickstart](../QUICKSTART.md)
- [Execution security model](../EXECUTION_SECURITY_MODEL.md)
- [MCP integration](../INTEGRATIONS/mcp.md)
- [Verification](../VERIFICATION.md)
- [ADR 0002 — canonical receipt bytes](../adr/0002-canonical-receipt-bytes.md)
- [ADR 0003 — normative artifact arbitration](../adr/0003-normative-artifact-arbitration.md)
- [`receipt.v5` normative signing-preimage specification](../../protocols/specs/receipts/receipt-v5.md)
- [`receipt.v5` conformance reference pack](../../reference_packs/receipt-v5/)
- [Gateway effect API: signed decision receipts](../architecture/gateway-effect-api.md)
