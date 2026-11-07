---
title: EvidencePack Verification
last_reviewed: 2026-06-29
---

# EvidencePack Verification

EvidencePacks bundle receipt and proof material so a run can be checked later
offline.

## Verify A Pack

```bash
helm-ai-kernel verify evidence-pack.tar
```

## API Routes

```text
POST /api/v1/evidence/export
POST /api/v1/evidence/verify
POST /api/v1/replay/verify
```

The HTTP contract is generated from `api/openapi/helm.openapi.yaml`.

`POST /api/v1/evidence/verify` checks the uploaded bundle against this
runtime's receipt signer and returns `outcome` plus `checks_run`, the checks
that ran: `bundle_format`, `bundle_seal`, `manifest_hashes`,
`required_artifacts` (only when a receipt requires a referenced artifact),
`receipt_signatures` and `receipt_chain`. Each check and the outcome is
`VERIFIED`, `FAILED` or `UNVERIFIABLE`. A seal or receipt signed by any other
key, including one the bundle carries about itself, is `UNVERIFIABLE` when
intact and never `VERIFIED`. The route evaluates no policy.

## When To Use This

- Share a governed run with a reviewer.
- Prove a denial or escalation without trusting the original process.
- Replay verification in CI or a release gate.

## Source Truth

- `docs/VERIFICATION.md`
- `docs/reference/http-api.md`
- `core/cmd/helm-ai-kernel/verify_cmd.go`
- `api/openapi/helm.openapi.yaml`
