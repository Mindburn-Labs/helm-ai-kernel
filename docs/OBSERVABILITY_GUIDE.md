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

## OTel Integration — Enabling & Configuration

### Enabling OTel in Code

Use the `WithOTel()` option to enable OpenTelemetry instrumentation on any HELM component:

```go
guardian := guardian.NewGuardian(signer, graph, pdp,
    guardian.WithOTel(),          // Enable OTel tracing + metrics
    guardian.WithOTelEndpoint("localhost:4317"),  // OTLP gRPC endpoint
)

executor := executor.NewSafeExecutor(guardian,
    executor.WithOTel(),          // Traces every tool execution
)
```

### Span Names

HELM emits the following spans (all prefixed `helm.`):

| Span | Parent | Description |
|---|---|---|
| `helm.guardian.evaluate` | root | Full PEP evaluation (6-gate pipeline) |
| `helm.guardian.gate.freeze` | evaluate | Freeze gate check |
| `helm.guardian.gate.context` | evaluate | Context gate check |
| `helm.guardian.gate.identity` | evaluate | Identity gate check |
| `helm.guardian.gate.egress` | evaluate | Egress gate check |
| `helm.guardian.gate.threat` | evaluate | Threat gate check |
| `helm.guardian.gate.delegation` | evaluate | Delegation gate check |
| `helm.guardian.pdp` | evaluate | Policy decision evaluation |
| `helm.guardian.sign` | evaluate | Ed25519/ML-DSA-65 decision signing |
| `helm.executor.execute` | root | Tool execution with receipt |
| `helm.proofgraph.append` | executor | ProofGraph node insertion |
| `helm.evidence.export` | root | EvidencePack export |
| `helm.evidence.verify` | root | EvidencePack verification |
| `helm.threatscan.ensemble` | evaluate | Ensemble threat scanning |
| `helm.budget.check` | evaluate | Budget/cost estimation check |
| `helm.memory.verify` | evaluate | Memory integrity verification |

### Exported Metrics (OTel)

In addition to the RED metrics listed above, `WithOTel()` exports:

| Metric | Type | Description |
|---|---|---|
| `helm.guardian.gate.duration` | Histogram | Per-gate latency (labeled by gate name) |
| `helm.threat.scanner.duration` | Histogram | Per-scanner latency in ensemble |
| `helm.threat.scanner.detections` | Counter | Detection count per scanner type |
| `helm.cost.estimated` | Counter | Pre-execution estimated cost (USD cents) |
| `helm.cost.actual` | Counter | Post-execution actual cost (USD cents) |
| `helm.memory.integrity.checks` | Counter | Memory integrity verification count |
| `helm.memory.integrity.failures` | Counter | Memory integrity failures |
| `helm.slo.violations` | Counter | SLO violation events |
| `helm.circuit_breaker.state_changes` | Counter | Circuit breaker state transitions |

---

## CloudEvents SIEM Export

**Package:** `core/pkg/otel/cloudevents.go`

HELM can export governance decisions as [CloudEvents](https://cloudevents.io/) for ingestion by SIEM systems (Splunk, Microsoft Sentinel, Elastic Security, Datadog).

### Setup

```go
exporter, err := otel.NewCloudEventsExporter(otel.CloudEventsConfig{
    Sink:       "https://siem.company.com/api/events",  // SIEM endpoint
    Source:     "helm/guardian/prod-1",
    AuthToken:  os.Getenv("SIEM_TOKEN"),
    BatchSize:  100,
    FlushInterval: 5 * time.Second,
})

guardian := guardian.NewGuardian(signer, graph, pdp,
    guardian.WithCloudEvents(exporter),
)
```

### Event Types

| CloudEvent Type | Triggered When |
|---|---|
| `helm.decision.allow` | PDP allows an effect |
| `helm.decision.deny` | PDP denies an effect |
| `helm.decision.escalate` | PDP escalates to human review |
| `helm.threat.detected` | Ensemble scanner flags a threat |
| `helm.budget.exhausted` | Tenant budget exceeded |
| `helm.slo.violation` | SLO target breached |
| `helm.circuit_breaker.open` | Circuit breaker trips open |
| `helm.trust.change` | Agent trust score changes |
| `helm.memory.tamper` | Memory integrity failure detected |

Each event includes: `decision_id`, `tenant_id`, `agent_id`, `tool_id`, `verdict`, `reason_code`, `cost_usd`, and `trace_id` for correlation with OTel traces.

---

## Grafana Dashboard Templates

Pre-built dashboards in `deploy/grafana/`:

1. **Decision Overview** — Throughput, latency distribution, verdict breakdown
2. **Tool Execution** — Tool call rates, success rates, latency by tool
3. **Error Budget** — SLO compliance, burn rate, budget remaining
4. **ProofGraph** — Node creation rate, graph size, condensation events
5. **Budget Tracking** — Spend rate, remaining budget, per-tenant breakdown
