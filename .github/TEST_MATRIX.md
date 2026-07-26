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
| External client contract | OpenAPI SDK parity, route contract tests, and generated-type parity |
| Deployment | Docker, Docker Compose, chart, and release smoke checks where environment support exists |
| Documentation | `make docs-coverage`, `make docs-truth`, docs-platform manifest/source checks |

## CI Branch Protection Baseline

The `main protection` ruleset is the enforcing source. This section describes
it; it does not define it. Read the live list rather than trusting this copy:

```bash
gh api /repos/Mindburn-Labs/helm-ai-kernel/rulesets/16024605 \
  --jq '.rules[] | select(.type=="required_status_checks")
        | [.parameters.required_status_checks[].context]'
```

As inspected on 2026-07-25 the ruleset is `active` on `refs/heads/main`,
requires a pull request and linear history, blocks deletion and
non-fast-forward pushes, and requires these 18 status checks in strict mode, so
a branch must also be up to date with `main` before it can merge:

`Quality PR profile`, `hygiene`, `kernel`, `contract-drift`, `python-sdk`,
`ts-sdk`, `rust-sdk`, `java-sdk`, `deployment-smoke`, `kind-smoke`,
`release-smoke`, `Coverage and truth`, `OpenSSF Scorecard`, `CodeQL (go)`,
`CodeQL (javascript-typescript)`, `CodeQL (python)`, `CodeQL (java-kotlin)`,
`Rust audit`.

These are not waivable. The ruleset's `bypass_actors` list is empty, so no
role — maintainer, admin, or app — can merge past a red required check.
Advisory suppression operates inside the quality profiles, on individual checks
that have not been promoted to blocking; it is not a route around the contexts
above.

Nightly runs `make quality-nightly`. New noisy gates remain Advisory until
their baselines are clean or `QUALITY_STRICT=1` promotes them to blocking.

No mock test defines canonical execution truth.
