# HELM Governance Telemetry

OpenTelemetry integration for governance observability.

## Overview

HELM emits governance telemetry as standard OpenTelemetry traces and metrics. This enables visibility into governance operations through any OTel-compatible backend: Jaeger, Grafana, Datadog, Google Cloud Monitoring, AWS X-Ray, etc.

## Attribute Schema

### Decision Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `helm.decision.verdict` | string | ALLOW, DENY, or ESCALATE |
| `helm.decision.reason_code` | string | Canonical reason code |
| `helm.decision.policy_ref` | string | Policy bundle/rule reference |
| `helm.decision.latency_ms` | float64 | Decision latency in milliseconds |

### Effect Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `helm.effect.type` | string | Effect class (E0–E4) |
| `helm.effect.risk_tier` | string | Risk tier (T1, T2, T3+) |
| `helm.effect.tool_name` | string | Tool/function name |

### Budget Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `helm.budget.consumed` | float64 | Cents consumed |
| `helm.budget.remaining` | float64 | Cents remaining |
| `helm.budget.ceiling` | float64 | Total budget ceiling |

### Receipt Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `helm.receipt.hash` | string | Receipt content hash |
| `helm.proofgraph.lamport` | int64 | ProofGraph Lamport height |

## Quick Start

```go
import helmotel "github.com/Mindburn-Labs/helm-oss/core/pkg/otel"

tracer, err := helmotel.NewGovernanceTracer(helmotel.Config{
    ServiceName: "helm-guardian",
    Endpoint:    "localhost:4317",
    Insecure:    true,
})
defer tracer.Shutdown(ctx)

// Trace a decision
tracer.TraceDecision(ctx, helmotel.DecisionEvent{
    Verdict:    "ALLOW",
    ReasonCode: "NONE",
    EffectType: "E1",
    ToolName:   "read_file",
    LatencyMs:  0.42,
})

// Measure decision timing automatically
done := tracer.MeasureDecision(ctx, "DENY", "BUDGET_EXCEEDED", "policy-1", "E2", "write_db")
// ... governance decision logic ...
done() // Records latency
```

## Grafana Dashboard

Import the included dashboard JSON to visualize governance telemetry:

```bash
# Point to your Grafana instance
curl -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @deploy/grafana/helm-governance-dashboard.json
```

## Disabling Telemetry

When OTel is not needed, use the no-op tracer:

```go
tracer := helmotel.NoopTracer()
```

This produces zero overhead — no spans, no metrics, no allocations.
