---
title: BENCHMARKS
---

# HELM Benchmark Methodology

## Claim

**HELM adds 75µs p99 overhead on the governed allow path** in the benchmark harness.

Deny path completes in 29µs p99. These numbers are measured under local benchmark conditions and scoped to the HELM execution boundary — not end-to-end network latency.

## What is measured

The HELM hot path is the incremental work added by HELM versus direct execution:

```
Guardian.EvaluateDecision → crypto.SignReceipt → SQLite store.Append
```

This chain runs on every governed tool call. It is the boundary overhead — the cost of governance, not the cost of the tool itself.

### Scenarios

| Scenario | What it measures |
|----------|-----------------|
| **baseline_no_helm** | Mock tool call (JSON marshal only) — no governance |
| **helm_allow** | Full governed allow: Guardian PRG eval → Ed25519 receipt sign → SQLite persist |
| **helm_deny** | Undeclared tool → fail-closed deny with signed decision |

### What is included in the HELM path

- PRG (Proof Requirement Graph) rule lookup and evaluation
- Effect envelope validation
- Decision record construction and signing (Ed25519)
- Receipt construction, canonicalization, and signing (Ed25519)
- SQLite WAL-mode persistence of signed receipt

### What is excluded

- Network I/O (upstream LLM call, proxy TCP)
- Export/verify (separate operational concern, not request-path)
- MCP transport overhead
- Cold start / process initialization
- TLS negotiation

## Results

Measured on commit `4e52909d`.

| Scenario | p50 | p95 | p99 | mean | σ | min | max |
|----------|-----|-----|-----|------|---|-----|-----|
| baseline_no_helm | 0µs | 1µs | 2µs | 0.17µs | 2.3µs | 0µs | 126µs |
| **helm_allow** | **46µs** | **54µs** | **75µs** | **48µs** | 11.1µs | 40µs | 409µs |
| helm_deny | 20µs | 23µs | 29µs | 21µs | 5.9µs | 18µs | 317µs |

**Incremental overhead (allow - baseline):**
- p99: 73µs
- mean: 48µs

## Environment

| Parameter | Value |
|-----------|-------|
| Machine | Apple M-series (arm64) |
| OS | macOS |
| Go version | 1.24.0 |
| CPU cores | 10 |
| Iterations | 10,000 per scenario |
| Warm-up | 100 iterations discarded before measurement |
| SQLite mode | WAL, PRAGMA synchronous=NORMAL |
| Signing | Ed25519 (crypto/ed25519, not CGo) |

## Reproduction

```bash
# Clone and build
git clone https://github.com/Mindburn-Labs/helm-oss.git
cd helm-oss

# Full overhead report (writes benchmarks/results/latest.json)
make bench-report

# Standard Go benchmarks (3 runs)
make bench

# Individual components
cd core && go test -bench=. -benchmem ./pkg/crypto/
cd core && go test -bench=. -benchmem ./pkg/store/
cd core && go test -bench=. -benchmem ./pkg/guardian/
cd core && go test -bench=. -benchmem ./benchmarks/
```

## Caveats

1. **Local benchmark harness only.** These numbers measure the HELM execution boundary in isolation, not end-to-end latency through a proxy or network stack.
2. **In-memory SQLite.** Production deployments using on-disk SQLite or Postgres will have higher store latency. WAL mode mitigates this but does not eliminate it.
3. **Single PRG rule.** The Guardian benchmark evaluates one rule. Complex policy graphs with many rules will increase eval time.
4. **No optional gates.** The benchmark runs Guardian without freeze controller, context guard, isolation checker, egress checker, threat scanner, or delegation store. Each enabled gate adds evaluation overhead.
5. **Warm run only.** Cold-start overhead (key generation, SQLite migration, PRG initialization) is excluded.

The claim is scoped: **75µs p99 on the governed allow hot path in the benchmark harness.** Do not generalize to all deployment topologies without additional measurement.

## Machine-readable output

`benchmarks/results/latest.json` contains structured results:

```json
{
  "helm_version": "0.3.0",
  "go_version": "go1.24.0",
  "hot_path_p99_us": 75,
  "baseline_p99_us": 2,
  "overhead_p99_us": 73,
  "overhead_under_5ms": true,
  "scenarios": [...]
}
```

## Competitive Comparison

HELM's headline 75µs p99 measures the **full governance path**: policy evaluation + Ed25519 signing + SQLite persistence. Competitors often report isolated policy evaluation numbers without cryptographic signing or persistence. To enable apples-to-apples comparison, HELM includes isolated benchmarks that break down each component.

| Component | Microsoft Agent OS | HELM | Factor |
|---|---|---|---|
| Policy rule evaluation (isolated CEL, cached) | 12µs/rule | **87ns** (`BenchmarkPolicyEval_CEL_Only`) | **137x faster** |
| Concurrent throughput | 72K ops/sec | **9.6M ops/sec** (`BenchmarkPolicyEval_Throughput`) | **133x higher** |
| Ed25519 receipt signing | N/A (not included) | **14µs** (`BenchmarkEd25519_SignOnly`) | — |
| Full governance path (eval + sign + persist) | Not claimed | **75µs p99** | — |

**How to run the isolated benchmarks:**

```bash
cd core && go test -bench='BenchmarkPolicyEval_CEL_Only|BenchmarkPolicyEval_Throughput|BenchmarkEd25519_SignOnly' -benchmem -count=5 ./benchmarks/
```

The full overhead report (`make bench-report`) includes a `competitive_comparison` section in `benchmarks/results/latest.json` with measured values for all components plus Microsoft's claimed numbers for reference.

**Key distinction:** Microsoft's Agent Governance Toolkit reports 12µs/rule for isolated policy evaluation and 72K ops/sec throughput. These numbers exclude cryptographic signing. HELM's full path includes Ed25519 signing on every decision and receipt, providing tamper-evident proof of governance that can be independently verified. The isolated CEL evaluation benchmark (`BenchmarkPolicyEval_CEL_Only`) is the direct comparison point.

## Post-Quantum Signing (ML-DSA-65)

HELM supports ML-DSA-65 (FIPS 204) post-quantum digital signatures via cloudflare/circl. These benchmarks show the overhead of PQ signing vs Ed25519:

| Operation | Ed25519 | ML-DSA-65 | Factor |
|---|---|---|---|
| Key generation | ~5µs | 146µs | 29x slower |
| Sign | ~20µs | 774µs | 39x slower |
| Verify | ~41µs | 42µs | **~1x (parity)** |
| Sign receipt | ~20µs | 298µs | 15x slower |
| Sign decision | ~20µs | 299µs | 15x slower |
| Verify receipt | ~41µs | 46µs | **~1x (parity)** |

**Key insight:** ML-DSA-65 verification is nearly as fast as Ed25519 (~42µs vs ~41µs). Signing is 15-39x slower but still under 1ms. For governance workloads where verification is more frequent than signing, ML-DSA-65 adds minimal overhead while providing quantum resistance.

Run with: `cd core && go test -bench=BenchmarkMLDSA -benchmem ./pkg/crypto/`

## Regression gating

Run `make bench-report` on release candidates. If `hot_path_p99_us` exceeds 5000 (5ms), the release should be investigated. The 5ms threshold is a conservative regression gate — the expected range is 50–200µs depending on hardware.
