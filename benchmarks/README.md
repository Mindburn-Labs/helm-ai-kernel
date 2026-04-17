# HELM Benchmark Harness

Measures the incremental latency HELM adds versus direct execution.

## What is measured

The hot path is: `Guardian.EvaluateDecision → crypto.SignReceipt → store.Append`

| Scenario | Description | In JSON report |
|----------|-------------|:-:|
| `baseline_no_helm` | Mock tool call with no governance — JSON marshal only | ✓ |
| `helm_allow` | Full governed allow: Guardian eval + Ed25519 sign + SQLite persist | ✓ |
| `helm_deny` | Undeclared tool → Guardian fail-closed deny evaluation | ✓ |
| `helm_allow_parallel` | Same as allow under goroutine concurrency | benchmark only |

> **Note:** `helm_deny` measures Guardian deny evaluation only (no receipt signing or store
> persistence in the deny path). This is the correct measurement — deny decisions are
> fail-closed at the Guardian boundary. The allow path includes sign + store.

## Running

```bash
# Full overhead report (10K iterations, JSON output)
make bench-report

# Standard Go benchmarks only
make bench

# Individual component benchmarks
cd core && go test -bench=. -benchmem ./pkg/crypto/
cd core && go test -bench=. -benchmem ./pkg/store/
cd core && go test -bench=. -benchmem ./pkg/guardian/
cd core && go test -bench=. -benchmem ./benchmarks/
```

## Output

`benchmarks/results/latest.json` — machine-readable report.

The schema shape is:

```json
{
  "helm_version": "0.4.0",
  "go_version": "go1.24.0",
  "go_os": "<os>",
  "go_arch": "<arch>",
  "num_cpu": <n>,
  "hot_path_p99_us": <float>,
  "baseline_p99_us": <float>,
  "overhead_p99_us": <float>,
  "overhead_under_5ms": true,
  "scenarios": [...]
}
```

See `benchmarks/results/latest.json` for actual measured values.

## Metrics per scenario

- p50, p95, p99
- mean, standard deviation
- min, max
- environment metadata (Go version, OS, arch, CPU count, timestamp)

## Hard rule

If measured overhead exceeds 5ms p99, the README claim is updated to match reality. Reality wins.
