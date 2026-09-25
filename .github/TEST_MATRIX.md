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
  --jq '.rules[]
        | select(.type=="pull_request" or .type=="required_status_checks")
        | {type, parameters}'
```

The ruleset is `active` on `refs/heads/main` and requires a pull request with
all review threads resolved (and zero required approvals), linear history, and
no deletion or non-fast-forward pushes.

CI v2 (2026-09-24) reports one required check, `ci / gate`, from
`.github/workflows/ci.yml`. It runs `make check`, which is the `merge` quality
profile with every gate blocking, plus the diff-aware dependency scan. The
ruleset should require `ci / gate` alone; the 18 per-job contexts it listed
before (`Quality PR profile`, `kernel`, the SDK jobs, `Coverage and truth`,
`OpenSSF Scorecard`, the CodeQL matrix, `Rust audit` and others) are no longer
reported.

These are not waivable. The ruleset's `bypass_actors` list is empty, so no
role — maintainer, admin, or app — can merge past a red required check.
`make check` runs with `--strict`, so no gate in the merge profile is advisory.

Nightly runs `make quality-nightly`. New noisy gates remain Advisory until
their baselines are clean or `QUALITY_STRICT=1` promotes them to blocking.

No mock test defines canonical execution truth.
