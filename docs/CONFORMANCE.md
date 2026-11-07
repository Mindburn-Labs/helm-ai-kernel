---
title: Conformance
last_reviewed: 2026-07-01
---

# Conformance

Conformance is the runnable check that HELM behaves like the public Kernel
contract says it behaves. This page states what each command checks, so a
result is never read as more than it covers.

## What `conform` Runs

| Command | What it checks |
| --- | --- |
| `helm-ai-kernel conform --profile SMB` | Gate G0, build identity, the only gate left. Exits 1 when it fails. With `--signed` it writes the report, its digest and a `.sig` file: an Ed25519 signature only when `HELM_SIGNING_KEY_HEX` holds a 64-byte private key, otherwise an explicitly unsigned digest. No release workflow sets that key, so `make conformance-release-report` produces the digest form. |
| `helm-ai-kernel conform --vector <file>` | One external failure vector file against its required assertions: receipt required, no connector dispatch, EvidencePack binding. It does not run the vector against a Kernel. |
| `helm-ai-kernel conform managed-agents claude-self-hosted` | Redacted live evidence for a self-hosted Claude managed-agents worker, written as an evidence pack and report. |
| `helm-ai-kernel conform vectors --json`, `helm-ai-kernel conform negative --json` | Nothing. They list the negative execution-boundary vectors (id, expected verdict, reason code, receipt and dispatch expectations). |

`helm-ai-kernel test conformance` forwards to `conform`.

## Run The Negative Vectors

The CLI only lists the vectors. The Go runner executes the vectors that have a
bound harness against a live Guardian and reports the rest as unbound:

```bash
cd core
go test -v ./pkg/conformance/negative -run TestDefaultCasesHoldTheirVectors
```

The log line reports how many vectors exist, how many are bound and how many
passed. Only the bound ones were exercised.

## Retired Levels

The `--level L1` and `--level L2` gate shortcuts were retired in HELM-756,
together with gates G1–G15 and GX. No EvidencePack could pass G1 and G7 at the
same time, and several gates passed without checking anything, so the levels
could not return a truthful result. `--level` still parses, but it exits 2 and
points to `conform vectors --json`. `L1`, `L2` and `L3` remain test-level labels in
`core/pkg/conformance`; the CLI proves none of them.

## Maintainer Test Targets

```bash
cd core
go test ./cmd/helm-ai-kernel -run 'TestConformLevelsAreRetired|TestConformRejectsRetiredProfilesAndGates' -count=1
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
