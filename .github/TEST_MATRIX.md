# HELM AI Kernel Test Matrix

This document defines the minimum source-backed test matrix for HELM AI Kernel. It
does not define gates for sibling repositories.

## Governance Boundaries

Systems that contribute to HELM AI Kernel execution truth must enforce:

- Offline determinism for ProofGraph, EvidencePack, receipt, and conformance
  fixtures.
- Fail-closed negative vectors for integration changes, so unhandled inputs
  return `DENY` or `ESCALATE` instead of silently dispatching.
- Source-backed OpenAPI and route parity for public HTTP claims.

## Required HELM AI Kernel Coverage

| Surface | Required signal |
| --- | --- |
| Go kernel and CLI | `go test` over `core/cmd/helm-ai-kernel`, boundary, contracts, conformance, and verifier packages |
| SDKs | Language-specific SDK gates and generated-type parity |
| ProofGraph and EvidencePack | Offline fixture verification and tamper checks |
| MCP and sandbox | Negative vectors for unknown server/tool/schema, missing grants, and authorization failures |
| Console | Static build, unit tests, and smoke check against generated API schema |
| Deployment | Docker, Docker Compose, chart, and release smoke checks where environment support exists |
| Documentation | `make docs-coverage`, `make docs-truth`, docs-platform manifest/source checks |

## CI Branch Protection Baseline

The following jobs should pass before merging to `main` unless a tracked
Advisory suppression explicitly explains the risk:

1. `quality-pr` / `make quality-pr`
2. `hygiene`
3. `kernel`
4. `contract-drift`
5. `deployment-smoke` and `release-smoke`
6. `codeql` and `scorecard`

Nightly runs `make quality-nightly`. New noisy gates remain Advisory until
their baselines are clean or `QUALITY_STRICT=1` promotes them to blocking.

No mock test defines canonical execution truth.
