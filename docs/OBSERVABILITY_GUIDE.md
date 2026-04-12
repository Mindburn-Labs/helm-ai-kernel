---
title: Observability Guide
---

# HELM Observability Guide

HELM provides comprehensive observability through OpenTelemetry integration, Prometheus metrics, structured logging, and audit timelines.

## OpenTelemetry Integration

**Package:** `core/pkg/observability/observability.go`

### Setup

```go
provider, err := observability.NewProvider(observability.ProviderConfig{
    ServiceName: "helm-guardian",
    Endpoint:    "localhost:4317",      // OTLP gRPC
    Sampler:     "always",             // always, never, ratio:0.1
    BatchTimeout: 5 * time.Second,
})
defer provider.Shutdown(ctx)
```

### RED Metrics (Rate, Errors, Duration)

| Metric | Type | Buckets/Labels |
|---|---|---|
| `helm.requests.total` | Counter | — |
| `helm.errors.total` | Counter | — |
| `helm.request.duration` | Histogram | 1ms, 5ms, 10ms, 50ms, 100ms, 500ms, 1s, 5s, 10s |
| `helm.operations.active` | UpDownCounter | — |

### Tracing

```go
ctx, span := observability.StartSpan(ctx, "Guardian.EvaluateDecision")
defer span.End()

// Track an operation with automatic RED metrics
err := observability.TrackOperation(ctx, provider, "execute", func() error {
    return doWork()
})
```

### HELM-Specific Attributes

| Attribute | Description |
|---|---|
| `helm.entity.id` | Governed entity identifier |
| `helm.governance.state` | Current governance state |
| `helm.governance.action` | Action being governed |
| `helm.policy.domain` | Policy domain |
| `helm.pdp.decision` | Policy decision (allow/deny) |
| `helm.pdp.latency_ms` | Policy evaluation latency |
| `helm.crypto.algorithm` | Signing algorithm (ed25519, ml-dsa-65) |
| `helm.compliance.jurisdiction` | Applicable jurisdiction |

## Prometheus Metrics

Expose at `:9090/metrics` (Prometheus scrape endpoint):

### Guardian Metrics

```promql
# Decision rate by verdict
rate(helm_guardian_decisions_total{verdict="ALLOW"}[5m])
rate(helm_guardian_decisions_total{verdict="DENY"}[5m])

# p99 decision latency
histogram_quantile(0.99, helm_guardian_decision_duration_seconds)
```

### Executor Metrics

```promql
# Tool call success rate
sum(rate(helm_executor_tool_calls_total{status="success"}[5m]))
/ sum(rate(helm_executor_tool_calls_total[5m]))
```

### ProofGraph Metrics

```promql
# Node creation rate by type
rate(helm_proofgraph_nodes_total{type="INTENT"}[5m])
rate(helm_proofgraph_nodes_total{type="TRUST_SCORE"}[5m])
```

### Budget Metrics

```promql
# Budget remaining per tenant
helm_budget_remaining{tenant_id="org-1"}
```

## AlertManager Rules

```yaml
groups:
  - name: helm-sre
    rules:
      - alert: GuardianLatencyHigh
        expr: histogram_quantile(0.99, helm_guardian_decision_duration_seconds) > 0.005
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Guardian p99 latency exceeds 5ms"

      - alert: BudgetExhausted
        expr: helm_budget_remaining < 20
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Tenant budget below 20%"

      - alert: EvidenceVerificationFailure
        expr: rate(helm_evidence_verification_total{result="failure"}[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Evidence verification failures detected"

      - alert: HighDenyRate
        expr: >
          sum(rate(helm_guardian_decisions_total{verdict="DENY"}[5m]))
          / sum(rate(helm_guardian_decisions_total[5m])) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "More than 50% of decisions are denials"
```

## Structured Logging

HELM uses Go's `slog` with trace ID correlation:

```json
{
  "level": "INFO",
  "msg": "decision",
  "trace_id": "abc123def456",
  "span_id": "0000000000000001",
  "decision_id": "dec-xyz789",
  "tenant_id": "org-1",
  "verdict": "ALLOW",
  "latency_ms": 48,
  "policy_version": "sha256:abc..."
}
```

Standard fields across all log entries:
- `trace_id` — W3C Trace Context propagation
- `span_id` — Current span identifier
- `tenant_id` — Multi-tenant isolation
- `decision_id` — Links to DecisionRecord
- `receipt_id` — Links to Receipt
- `tool_id` — Governed tool identifier
- `latency_ms` — Operation duration

## Audit Timeline

**Package:** `core/pkg/observability/audit_timeline.go`

Unified queryable log combining all governance events:

```go
timeline := observability.NewAuditTimeline()

// Query by run ID
entries := timeline.Query(observability.TimelineQuery{
    RunID:     "run-123",
    EntryType: observability.EntryTypeDecision,
    From:      startTime,
    To:        endTime,
    Limit:     100,
})
```

Entry types: `ACTION`, `TOOL_CALL`, `DECISION`, `PROOF`, `RECONCILIATION`, `ESCALATION`, `EVIDENCE`

## Grafana Dashboard Templates

Pre-built dashboards in `deploy/grafana/`:

1. **Decision Overview** — Throughput, latency distribution, verdict breakdown
2. **Tool Execution** — Tool call rates, success rates, latency by tool
3. **Error Budget** — SLO compliance, burn rate, budget remaining
4. **ProofGraph** — Node creation rate, graph size, condensation events
5. **Budget Tracking** — Spend rate, remaining budget, per-tenant breakdown
