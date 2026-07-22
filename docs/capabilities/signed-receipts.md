---
title: Signed Receipts
last_reviewed: 2026-07-16
---

<!-- quantum_posture: this page documents classical Ed25519 receipt signing and does not claim post-quantum or hybrid cryptographic protection. -->

# Signed Receipts

A HELM receipt is the signed record of a governed decision. It lets an operator
check what the boundary decided without trusting a chat transcript or dashboard.

## What Receipts Prove

- The decision status: `ALLOW`, `DENY`, or `ESCALATE`.
- The reason code and decision metadata.
- The receipt hash and signature material.
- The link between the request, output, and governed boundary.

For workstation receipts, integrity and signer identity are deliberately
separate checks. An integrity check shows that receipt contents match the
public key named by the receipt. A trusted-signer check compares that key with
an expected local or caller-supplied public key. A receipt is not trusted just
because its self-declared signature verifies.

## Verify A Local Hook Receipt

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

The command succeeds only when both `integrity` and `trusted` are true. To
verify a copied receipt, pass `--trusted-public-key-file <path>` for one
expected Ed25519 public key, or `--trusted-signers-file <path>` for a
versioned caller-owned allowlist during signer rotation. Do not accept a public
key bundled by the receipt itself as the trust decision. In production,
verification requires one of those explicit sources; it does not fall back to
local signer state.

## Inspect Runtime Receipts

```bash
helm-ai-kernel receipts tail --agent <agent-id> --server http://127.0.0.1:7714
```

## Source Truth

- `protocols/specs/rfc/receipt-format-v1.md`
- `core/cmd/helm-ai-kernel/receipts_cmd.go`
- `core/cmd/helm-ai-kernel/receipt_routes.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `docs/VERIFICATION.md`
