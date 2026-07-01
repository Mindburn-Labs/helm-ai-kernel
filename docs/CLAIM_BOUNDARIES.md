---
title: Claim Boundaries
last_reviewed: 2026-07-01
---

# Claim Boundaries

HELM AI Kernel is public OSS. It is safe to describe the local kernel,
CLI/API, receipts, verification, MCP boundary checks, workstation hook receipts,
and local onboarding proof path when the claim points to source, tests, or a
published release asset.

## Public Claims

- HELM AI Kernel is a fail-closed execution firewall for AI agents.
- Dangerous or unapproved selected effects can be denied before dispatch when
  they pass through a HELM adapter, wrapper, hook, or API route.
- Decisions produce signed receipts that can be verified offline.
- EvidencePacks and release assets can be checked from local material without a
  hosted service.
- The public conformance proof path supports `L1` and `L2` CLI shortcuts.
- The OpenAI-compatible proxy and MCP authorization routes are local boundary
  surfaces, not claims of model-provider control.

## Not Public Claims

- No hosted Enterprise automation production deployment is claimed by this repo.
- No named buyer rollout, buyer certification, or compliance certification is
  claimed by this repo.
- No public paid signup or paid production account activation is claimed here.
- No full operating-system, browser, IDE, eBPF, seccomp, TPM, hardware enclave,
  packet blocking, or proprietary hosted-agent control is claimed unless a
  tested source path proves the specific effect crossed HELM.
- No `L4` conformance claim is public. `L3` remains source/test coverage until
  a public proof path is wired and tested.

## Source Truth

- `CLAIMS.md`
- `docs/QUICKSTART.md`
- `docs/CONFORMANCE.md`
- `docs/reference/http-api.md`
- `core/cmd/helm-ai-kernel`
- `core/pkg/conformance`
- `api/openapi/helm.openapi.yaml`

## Validation

```bash
python3 scripts/check_documentation_truth.py
go test ./core/cmd/helm-ai-kernel -run TestConformLevelAliasesSeedBaselineEvidence -count=1
go test ./core/pkg/conformance -run 'TestCoreSuiteRegistrationAndRun|TestOWASP_LLM_Top10' -count=1
```
