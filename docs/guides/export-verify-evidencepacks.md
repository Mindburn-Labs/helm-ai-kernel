---
title: Export And Verify EvidencePacks
last_reviewed: 2026-06-29
---

# Export And Verify EvidencePacks

Use EvidencePacks when a governed run needs to be checked later without
trusting the original dashboard or process.

## Verify A Pack

```bash
helm-ai-kernel verify evidence-pack.tar
```

## Verify A Workstation Decision

```bash
helm-ai-kernel workstation verify-decision \
  --receipt ~/.helm-ai-kernel/receipts/hooks/<decision>.json
```

Integrity (`integrity_valid`) and signer trust (`signer_trusted`) are separate
verdicts: trust requires the workstation public key pinned out of band — see
[local signer and trusted verification](../reference/workstation-governance.md#local-signer-and-trusted-verification).
Pre-v0.7.3 derivable-seed receipts remain untrusted.

## HTTP Evidence Routes

The OpenAPI contract owns the HTTP evidence export and verification routes.
Start with:

```text
POST /api/v1/evidence/export
POST /api/v1/evidence/verify
POST /api/v1/replay/verify
```

Download the current contract from `/openapi.yaml`.

## Source Truth

- `docs/VERIFICATION.md`
- `docs/reference/http-api.md`
- `core/cmd/helm-ai-kernel/verify_cmd.go`
- `core/cmd/helm-ai-kernel/workstation_m3_cmd.go`
- `api/openapi/helm.openapi.yaml`
