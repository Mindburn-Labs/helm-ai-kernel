---
title: Conformance
last_reviewed: 2026-07-01
---

# Conformance

Conformance is the runnable check that HELM behaves like the public Kernel
contract says it behaves.

## Run The Public Levels

```bash
helm-ai-kernel conform --level L1 --json
helm-ai-kernel conform --level L2 --json
helm-ai-kernel conform negative --json
helm-ai-kernel conform vectors --json
```

`L1` covers the local proof path: canonical inputs, receipt shape, offline
verification, and checkpoint roots.

`L2` adds the MCP execution firewall: quarantine, tool-list/call consistency,
schema pinning, direct-bypass denial, scoped approvals, revocation, expiry, and
receipt emission.

Higher levels are not public shortcuts in the Kernel docs. Treat any `L3` or
`L4` material as source/test coverage until a public command and test-backed
proof path exists.

## Maintainer Test Targets

```bash
cd core
go test ./cmd/helm-ai-kernel -run TestConformLevelAliasesSeedBaselineEvidence -count=1
go test ./pkg/conformance -run 'TestCoreSuiteRegistrationAndRun|TestOWASP_LLM_Top10' -count=1
```

## Interpreting Failures

| Failure area | First check |
| --- | --- |
| Canonicalization | Input JSON shape and sorted keys |
| Receipts | Decision id, verdict, reason code, and signature material |
| MCP boundary | Server id, tool list, schema pin, approval scope, and effect |
| Revocation or expiry | Approval receipt, revocation receipt, and TTL |
| EvidencePack | Indexed file hashes and receipt bytes |

Conformance is local proof. It does not claim provider certification, hosted
deployment status, or broad platform control.
