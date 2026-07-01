---
title: Signed Receipts
last_reviewed: 2026-06-29
---

# Signed Receipts

A HELM receipt is the signed record of a governed decision. It lets an operator
check what the boundary decided without trusting a chat transcript or dashboard.

## What Receipts Prove

- The decision status: `ALLOW`, `DENY`, or `ESCALATE`.
- The reason code and decision metadata.
- The receipt hash and signature material.
- The link between the request, output, and governed boundary.

## Verify A Local Hook Receipt

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

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
