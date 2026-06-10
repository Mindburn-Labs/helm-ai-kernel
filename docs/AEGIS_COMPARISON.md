---
title: AEGIS Comparison
last_reviewed: 2026-06-10
---

# AEGIS Comparison — Pre-Execution Firewall Evidence Parity

## Audience

Maintainers and reviewers positioning HELM against AEGIS (arXiv
2603.12621), the open-source pre-execution firewall that enforces policy
between agents and tools and emits Ed25519-signed, SHA-256 hash-chained
records per intercepted call.

## Source Truth

- AEGIS paper: <https://arxiv.org/abs/2603.12621> (all AEGIS figures
  below are AEGIS's own reported numbers, not HELM measurements)
- Evidence-integrity parity proofs: `core/pkg/store/aegis_evidence_parity_test.go`
  (`cd core && go test ./pkg/store/ -run TestAegis`)
- Overhead benchmarks: `core/pkg/mcp/aegis_overhead_bench_test.go`
  (`cd core && go test ./pkg/mcp/ -bench BenchmarkPreExecution -run '^$' -benchmem`)
- Attack-suite analogs: `core/pkg/mcp/mcptox_test.go` (tool poisoning,
  rug pull, typosquatting, hidden instructions, schema manipulation,
  cross-server), `make test-owasp`, `make crucible`

## Why this matters

AEGIS ships the same wedge HELM occupies — fail-closed pre-execution
policy enforcement with content-addressed, tamper-evident per-call
evidence — as an OSS repo with published benchmarks. It validates the
category and raises the evidence bar. This page records where HELM
stands, with every HELM claim bound to a test or benchmark in this repo.

## Comparison

| Dimension | AEGIS (reported) | HELM (source-backed) |
| --- | --- | --- |
| Interception model | Out-of-process proxy between agent and tools; zero code changes | In-process kernel boundary (`ExecutionFirewall`) plus proxy/gateway modes (`helm-ai-kernel proxy`, MCP gateway) — zero agent code changes in proxy mode |
| Per-call evidence | Ed25519-signed, SHA-256 hash-chained record per intercepted call | SHA-256 hash-chained append-only audit store with tamper detection (`TestAegisParityHashChainPerInterceptedCall`, `TestAegisParityTamperDetection`); sealed JCS/SHA-256 `ExecutionBoundaryRecord` per decision; Ed25519 signatures over chain heads and records via key ring/SoftHSM (`TestAegisParityEd25519SignedChainHead`); standardized export via AAT JSONL (`helm-ai-kernel export aat`) — **parity reached** |
| Exportable proof | Per-call records | `ExportBundle`/`VerifyBundle` re-verifiable bundles (`TestAegisParityExportedBundleReverifies`), EvidencePacks (JCS canonical manifests), AAT export mode |
| Overhead | ~8.3ms median per call | In-process authorize path measured at ~6.2µs allow / ~5.7µs deny per call (Apple M4 Max, `BenchmarkPreExecutionAuthorize*`; machine-specific — regenerate with the bench command above; `make bench-report` for the canonical harness). Proxy-mode deployments add transport cost not captured here. |
| Attack coverage | 48 curated attacks blocked across 14 frameworks | MCPTox suite (6 attack categories incl. tool poisoning, rug pull, typosquat, hidden instructions, schema manipulation, cross-server), OWASP MCP threat suite (`make test-owasp`), crucible L1–L3 conformance. Different corpus — a direct run of the AEGIS 48-attack suite has not been performed in-repo. |
| False positives | ~1.2% FP | Not directly comparable: HELM verdicts are deterministic policy evaluation (CEL/WASM, scope, schema pin), not a probabilistic classifier — FP rate is a property of the configured policy, not the engine. Fail-closed defaults (unknown server/tool/scope = DENY) are the conservative direction. |
| Kill switch / HITL | Kill switch + human-in-the-loop approvals | Quarantine registry (default-deny until approved), approval ceremonies (`helm-ai-kernel approvals`), freeze gate (Guardian Gate 1), ESCALATE verdict path |
| Formal grounding | — | TLA+-verified guardian pipeline (`proofs/GuardianPipeline.tla`), golden fixtures, conformance levels |

## Honest gaps / follow-ups

1. **AEGIS attack-suite replay.** HELM has not executed AEGIS's specific
   48-attack corpus. If/when the corpus is published in a runnable form,
   replaying it under the MCPTox harness would make the coverage row
   apples-to-apples. Until then, do not claim a block rate against it.
2. **End-to-end proxy-mode latency.** The benchmark above measures the
   in-process decision path. A published proxy-mode end-to-end number
   (comparable to AEGIS's 8.3ms network-hop figure) should come from the
   canonical bench harness (`make bench-report`), not this page.
3. **Public one-pager.** This is the internal source-backed comparison.
   Public claim wording must go through the claims registry flow before
   any external use.
