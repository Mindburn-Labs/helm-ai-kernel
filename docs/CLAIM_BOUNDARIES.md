---
title: Claim Boundaries
last_reviewed: 2026-08-21
---

# Claim Boundaries

HELM AI Kernel is public OSS. The public docs may describe the local kernel,
CLI/API, receipts, verification, MCP boundary checks, workstation hook
receipts, and local proof path when those claims are backed by source, tests,
or release artifacts.

## Public Claims

- HELM AI Kernel is a fail-closed execution firewall for AI agents.
- Selected effects can be denied before dispatch when they pass through a HELM
  adapter, wrapper, hook, proxy, or API route.
- Unknown or unapproved MCP paths can escalate and stay blocked until a
  credential-verified durable dispatch admission exists. Local
  `mcp approve` does not mint that authority.
- Decisions, approvals, and revocations write local receipts.
- EvidencePacks can be checked from local material without trusting a hosted
  service.
- `helm-ai-kernel conform` runs the G0 build-identity gate and checks a single
  external failure vector. It lists the negative execution-boundary vectors
  without running them, and it has no `L1` or `L2` level shortcuts: `--level`
  was retired and exits 2.

## Coverage Labels

| Surface | Label | Why |
| --- | --- | --- |
| Local coding-agent hooks (`setup claude-code`, `codex`, `hermes`, `deepseek`) | observed-only | The client decides which calls reach the hook, and the hook classifies command text. It denies what it recognizes and what it cannot evaluate statically, but it is defense in depth, not a boundary. |

## Not Public Claims

- No hosted Enterprise deployment is claimed by this repo.
- No named buyer rollout is claimed by this repo.
- No public paid signup or paid account activation is claimed here.
- No full operating-system, browser, IDE, eBPF, seccomp, TPM, hardware enclave,
  packet blocking, or proprietary hosted-agent control is claimed unless a
  tested path proves the specific effect crossed HELM.
- No `L4` conformance claim is public. `L1`, `L2` and `L3` are test-level
  labels in `core/pkg/conformance`; none has a public CLI or API proof path.

## Local Checks

```bash
python3 scripts/check_documentation_truth.py
cd core
go test ./cmd/helm-ai-kernel -run 'TestConformLevelsAreRetired|TestConformRejectsRetiredProfilesAndGates' -count=1
go test ./pkg/conformance -run 'TestSuiteRunResultBranches|TestDefaultNegativeBoundaryVectors' -count=1
```
