# HELM OpenTelemetry Integration Guide

## Overview

HELM ships with a production-ready OTel governance tracer at
`pkg/otel/governance_tracer.go`. This guide covers configuration
and integration with popular observability backends.

## Quick Start

```go
import helmotel "github.com/Mindburn-Labs/helm-oss/core/pkg/otel"

// Create tracer — connects to OTLP gRPC endpoint
tracer, err := helmotel.NewGovernanceTracer(helmotel.Config{
    ServiceName: "helm-guardian",
    Endpoint:    "localhost:4317",
    Insecure:    true,
})
defer tracer.Shutdown(ctx)
```

## Exported Metrics

| Metric | Type | Description |
|:--|:--|:--|
| `helm.decisions.total` | Counter | Total governance decisions (by verdict, effect) |
| `helm.denials.total` | Counter | Total denials (by reason code, effect) |
| `helm.budget.utilization` | Gauge | Budget consumption ratio (0-1) |
| `helm.decision.latency` | Histogram | Decision latency in milliseconds |

## Exported Traces

| Span | Attributes |
|:--|:--|
| `helm.governance.decision` | verdict, reason_code, policy_ref, effect_type, risk_tier, tool_name, latency_ms, lamport |
| `helm.governance.denial` | verdict=DENY, reason_code, policy_ref, effect_type, tool_name |

## Backend Configuration

### Jaeger

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:1.57
    ports:
      - "4317:4317"   # OTLP gRPC
      - "16686:16686" # UI
```

```go
tracer, _ := helmotel.NewGovernanceTracer(helmotel.Config{
    ServiceName: "helm-guardian",
    Endpoint:    "localhost:4317",
    Insecure:    true,
})
```

### Grafana + Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'helm-guardian'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: '/metrics'
```

Export via OTLP to Grafana Tempo for traces, Prometheus for metrics:

```go
tracer, _ := helmotel.NewGovernanceTracer(helmotel.Config{
    ServiceName: "helm-guardian",
    Endpoint:    "tempo.internal:4317",
})
```

### Datadog

```go
tracer, _ := helmotel.NewGovernanceTracer(helmotel.Config{
    ServiceName: "helm-guardian",
    Endpoint:    "localhost:4317", // Datadog Agent OTLP endpoint
})
```

### Langfuse

```bash
# Set environment variables for Langfuse OTLP endpoint
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otel.langfuse.com
export OTEL_EXPORTER_OTLP_HEADERS="x-api-key=your-langfuse-key"
```

### Google Cloud Monitoring

```go
tracer, _ := helmotel.NewGovernanceTracer(helmotel.Config{
    ServiceName: "helm-guardian",
    Endpoint:    "monitoring.googleapis.com:443",
})
```

## `helm.yaml` Configuration

```yaml
telemetry:
  otel:
    enabled: true
    endpoint: "localhost:4317"
    insecure: true
    service_name: "helm-guardian"
  prometheus:
    enabled: true
    listen: ":9090"
    path: "/metrics"
```

## No-Op Mode

When OTel is disabled, HELM uses a no-op tracer with zero overhead:

```go
tracer := helmotel.NoopTracer()
```

## Convenience: MeasureDecision

```go
// Automatically measures duration and traces the decision
done := tracer.MeasureDecision(ctx, "ALLOW", "", "policy:v1", "E1", "read_file")
// ... execute the decision ...
done() // Records latency and emits trace
```

## Custom Attributes

All HELM OTel attributes use the `helm.*` namespace:

```
helm.decision.verdict        — ALLOW | DENY
helm.decision.reason_code    — e.g., "PDP_DENY", "BUDGET_EXCEEDED"
helm.decision.policy_ref     — e.g., "helm:v0.3.0"
helm.decision.latency_ms     — Decision latency
helm.effect.type             — E0-E4
helm.effect.risk_tier        — LOW, MEDIUM, HIGH, CRITICAL
helm.effect.tool_name        — Tool being governed
helm.budget.consumed/remaining/ceiling
helm.receipt.hash            — Receipt content hash
helm.proofgraph.lamport      — Lamport clock value
helm.a2a.origin_agent/target_agent/negotiation_result
```
