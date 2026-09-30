---
title: Conformance
last_reviewed: 2026-07-01
---

# Conformance

Conformance is the runnable check that HELM behaves like the public Kernel
contract says it behaves.

## Run The Conformance Vectors

```bash
helm-ai-kernel conform negative --json
helm-ai-kernel conform vectors --json
```

The `--level L1` and `--level L2` gate shortcuts were retired in HELM-756,
together with gates G1–G15 and GX. No EvidencePack could pass G1 and G7 at the
same time, and several gates passed without checking anything, so the levels
could not return a truthful result. `--level` still parses, but it exits 2 and
points here. The only gate that still runs is G0 (build identity). The release
pipeline signs a G0 report with `make conformance-release-report`.

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

Conformance is local proof for the public Kernel contract above.
