---
title: Signed Receipts
last_reviewed: 2026-08-19
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
verify a copied receipt, pass `--trusted-public-key-file <path>` for the
expected Ed25519 public key; do not accept a public key bundled by the receipt
itself as the trust decision.

## Verify A Kernel Evaluate Receipt Offline

This is Foundation/offline `receipt.v5` verify. It is not AI OS live, not
helm-ai-kernel#859, and not self-attested EvidencePack verification.

Evaluate persist writes a copyable JSON file under
`<data-dir>/receipts/evaluate/<receipt_id>.json` plus
`expected-ed25519.pub`. A stranger with the brew CLI (Kernel off) can check
that file:

```bash
helm-ai-kernel verify receipt \
  --receipt <receipt.v5.json> \
  --trusted-public-key-file <expected-ed25519.pub>
```

Exit 0 only when integrity and signer trust both hold against the
caller-supplied key. A public key embedded in the receipt is not enough.
`verify --bundle` / `--allow-self-attested` and
`workstation verify-decision` are different paths.

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
