# HELM OSS Contracts Package Source Owner

## Audience

Use this file when changing shared request, verdict, receipt, evidence, replay, approval, role, effect, or execution-boundary contract types.

## Responsibility

`core/pkg/contracts` owns the Go contract model that the CLI, server, SDK examples, schemas, conformance fixtures, receipt verifier, and public reference docs depend on. Public docs may explain the supported fields and flows, but this package is the source-owner for in-process contract semantics.

## Public Status

Classification: `public-hub`.

Public docs should link here from:

- `helm-oss/reference/execution-boundary`
- `helm-oss/reference/http-api`
- `helm-oss/reference/json-schemas`
- `helm-oss/reference/protocols-and-schemas`
- `helm-oss/verification`
- `helm-oss/conformance`

## Source Map

- Decision and verdict contracts: `decision.go`, `decision_request.go`, `verdict.go`, `risk_summary.go`.
- Receipt and evidence contracts: `receipt.go`, `receipt_hash.go`, `evidence.go`, `evidence_contract.go`, `replay.go`.
- Boundary and effect contracts: `execution_boundary.go`, `effect_types.go`, `effect_catalog.go`, `taint.go`.
- Approval and role contracts: `approval.go`, `approval_binding.go`, `role.go`, `delegation_proof.go`.
- Wire-format anchors: `*.proto`, `schemas/`, and `schema_validation_test.go`.

## Documentation Rules

- Do not document a public field unless it is backed by this package, JSON schema, OpenAPI, SDK examples, or conformance fixtures.
- Changes to receipt hashing, replay material, verdict naming, or boundary effects require public reference updates before release.
- Experimental fields must stay source-only until schemas and conformance coverage are added.

## Validation

Run:

```bash
cd core
go test ./pkg/contracts -count=1
cd ..
make docs-coverage docs-truth
```
