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

Each check ends `VERIFIED`, `FAILED`, `UNVERIFIABLE` or `NOT_RUN`. A check the
pack gives no input to is `NOT_RUN`, never passed, and the result states the
passed, failed and not-run counts separately. Exit 0 means no check failed and
every required check held; it does not mean every check ran. Evidence a pack
carries is validated whether or not anything requires it. Every check except
`roots` and `evidence_pack_seal`, which read the pack through the seal code,
reads it through an `os.Root` on its directory: a path or symbolic link
that leaves the pack, an absolute symbolic link and a file that is not a
regular file are refused and fail the check that wanted them. A recorded tape
is replayed with the code `helm-ai-kernel replay` runs. `helm-ai-kernel evidence inspect`
reaches the same verdict through the same code and exits the same way. The
checks and what requires each are listed in
[Receipts](../VERIFICATION.md#what-the-result-covers).

## API Routes

```text
POST /api/v1/evidence/export
POST /api/v1/evidence/verify
```

The HTTP contract is generated from `api/openapi/helm.openapi.yaml`.

`POST /api/v1/evidence/verify` checks the uploaded bundle against this
runtime's receipt signer and returns `outcome` plus `checks_run`, the checks
that ran: `bundle_format`, `bundle_seal`, `manifest_hashes`,
`required_artifacts` (only when a receipt requires a referenced artifact),
`receipt_signatures` and `receipt_chain`. Each check and the outcome is
`VERIFIED`, `FAILED` or `UNVERIFIABLE`. A seal or receipt signed by any other
key, including one the bundle carries about itself, is `UNVERIFIABLE` when
intact and never `VERIFIED`. The route evaluates no policy. The route and the
CLI derive their outcome with one rule: any failed check fails the result, an
unverifiable or missing required check leaves it `UNVERIFIABLE`, and a result
in which no check ran is never a pass.

## When To Use This

- Share a governed run with a reviewer.
- Prove a denial or escalation without trusting the original process.
- Check an exported bundle in CI or a release gate.

## Source Truth

- `docs/VERIFICATION.md`
- `docs/reference/http-api.md`
- `core/cmd/helm-ai-kernel/verify_cmd.go`
- `api/openapi/helm.openapi.yaml`
