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

## When To Use This

- Share a governed run with a reviewer.
- Prove a denial or escalation without trusting the original process.
- Replay verification in CI or a release gate.

## Source Truth

- `docs/VERIFICATION.md`
- `docs/reference/http-api.md`
- `core/cmd/helm-ai-kernel/verify_cmd.go`
- `api/openapi/helm.openapi.yaml`
