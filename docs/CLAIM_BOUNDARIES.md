---
title: Claim Boundaries
last_reviewed: 2026-07-14
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
- Unknown or unapproved MCP paths can escalate into local scoped approval.
- Decisions, approvals, and revocations write local receipts.
- EvidencePacks can be checked from local material without trusting a hosted
  service.
- Codex project setup can record a signed local lifecycle transaction and a
  Kernel-only synthetic denial without claiming a real client session.
- The public conformance proof path supports `L1` and `L2` CLI shortcuts.

## Not Public Claims

- No hosted Enterprise deployment is claimed by this repo.
- No named buyer rollout is claimed by this repo.
- No public paid signup or paid account activation is claimed here.
- No full operating-system, browser, IDE, eBPF, seccomp, TPM, hardware enclave,
  packet blocking, or proprietary hosted-agent control is claimed unless a
  tested path proves the specific effect crossed HELM.
- No local config, lifecycle receipt, or synthetic denial is a claim that Codex
  or Claude Code loaded the generated configuration. Native-client review must
  identify the exact configured hook class and routed MCP call exercised.
- No `L4` conformance claim is public. `L3` remains source/test coverage until
  a public proof path is wired and tested.

## Local Checks

```bash
python3 scripts/check_documentation_truth.py
cd core
go test ./cmd/helm-ai-kernel -run TestConformLevelAliasesSeedBaselineEvidence -count=1
go test ./pkg/conformance -run 'TestCoreSuiteRegistrationAndRun|TestOWASP_LLM_Top10' -count=1
```
