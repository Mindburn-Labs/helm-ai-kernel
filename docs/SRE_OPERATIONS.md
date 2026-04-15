---
title: SRE Operations Guide
---

# HELM SRE Operations Guide

HELM includes a comprehensive SRE (Site Reliability Engineering) stack for governing AI agent reliability. This guide covers SLO tracking, error budgets, circuit breakers, risk budgets, and incident response.

## SLO Tracking & Error Budgets

**Package:** `core/pkg/observability/slo.go`

HELM's SLO tracker monitors service level objectives across all governed operations with real-time burn rate alerting and error budget management.

### Defining SLOs

```go
tracker := observability.NewSLOTracker()

tracker.SetTarget(&observability.SLOTarget{
    SLOID:       "slo-guardian-allow",
    Name:        "Guardian Allow Path Latency",
    Operation:   "execute",
    LatencyP99:  75 * time.Microsecond,
    SuccessRate: 0.999,  // 99.9% success
    WindowHours: 24,
})
```

**Supported operations:** `compile`, `plan`, `execute`, `verify`, `replay`, `escalation`

### Recording Observations

```go
tracker.Record(observability.SLOObservation{
    Operation: "execute",
    Latency:   52 * time.Microsecond,
    Success:   true,
})
```

### Checking SLO Status

```go
status := tracker.Status("execute")
// status.InCompliance   — true if within SLO
// status.BurnRate       — >1.0 means error budget is being consumed faster than allowed
// status.ErrorBudgetLeft — percentage of error budget remaining
// status.CurrentP99     — observed p99 latency in ms
```

### Error Budget Model

Error budget = `1.0 - SuccessRate`. For a 99.9% SLO, the error budget is 0.1% of total requests.

**Burn rate** = `observed_error_rate / error_budget`. A burn rate of 1.0 means the budget is consumed exactly at the allowed rate. A burn rate of 10.0 means the budget will exhaust 10x faster than planned.

| Burn Rate | Meaning | Recommended Action |
|---|---|---|
| < 1.0 | Within budget | Normal operations |
| 1.0-2.0 | At budget limit | Monitor closely |
| 2.0-5.0 | Exceeding budget | Investigate root cause |
| 5.0-10.0 | Rapid exhaustion | Escalate, consider throttle |
| > 10.0 | Critical | Freeze deployments, trigger incident |

### SLI Definitions

**Package:** `core/pkg/observability/sli.go`

SLIs (Service Level Indicators) define what metrics back each SLO. HELM supports multi-source SLIs:

```go
registry := observability.NewSLIRegistry()
registry.Register(observability.SLIDefinition{
    SLIID:           "sli-guardian-latency",
    Name:            "Guardian Execution Latency",
    Operation:       "execute",
    Source:          observability.SLISourceMetric,  // METRIC, LOG, TRACE, or PROBE
    Unit:            "ms",
    GoodEventQuery:  "helm_guardian_decision_duration_seconds < 0.005",
    TotalEventQuery: "helm_guardian_decisions_total",
    LinkedSLOID:     "slo-guardian-allow",
})
```

---

## Circuit Breakers

**Package:** `core/pkg/util/resiliency/client.go`

HELM's circuit breaker protects against cascading failures with a three-state machine.

### State Machine

```
CLOSED ──(failures >= threshold)──> OPEN ──(timeout elapsed)──> HALF_OPEN
  ^                                                                |
  └──────────────(success in half-open)────────────────────────────┘
  └──────────────(failure in half-open)──> OPEN
```

### Configuration

```go
breaker := resiliency.NewCircuitBreaker(
    "guardian-backend",  // name
    5,                   // failure threshold
    10 * time.Second,    // reset timeout
)

// Check before making request
if !breaker.Allow() {
    // Circuit is open — skip the call
    return ErrCircuitOpen
}

// On success
breaker.Success()

// On failure
breaker.Failure()
```

### EnhancedClient

The `EnhancedClient` combines circuit breaking with exponential backoff and jitter:

```go
client := resiliency.NewEnhancedClient()
resp, err := client.Do(req)
```

Features:
- **Exponential backoff:** `base * 2^attempt + random(0, 50ms)`
- **Max 3 retries** (configurable)
- **W3C Trace Context injection** (traceparent header)
- **Circuit breaker integration** per request
- **Fail-open on 4xx** (client errors not retried), **fail-closed on 5xx**

---

## Risk Budgets

**Package:** `core/pkg/budget/risk_budget.go`

Risk budgets extend basic cost budgets with risk-weighted limits, blast radius caps, and autonomy management.

### Risk Levels & Weights

| Risk Level | Weight | Autonomy Threshold |
|---|---|---|
| LOW | 1.0x | Autonomy >= 10 |
| MEDIUM | 2.0x | Autonomy >= 40 |
| HIGH | 5.0x | Autonomy >= 70 |
| CRITICAL | 10.0x | Never autonomous |

### Configuring Risk Budgets

```go
enforcer := budget.NewRiskEnforcer()
enforcer.SetBudget(&budget.RiskBudget{
    TenantID:         "org-1",
    ComputeCapMillis: 60000,  // 60s max compute
    BlastRadiusCap:   100,    // max 100 affected resources
    RiskScoreCap:     500.0,  // aggregate risk ceiling
    AutonomyLevel:    80,     // start at high autonomy
    UncertaintyScore: 0.2,
})
```

### Risk Checks

```go
decision := enforcer.CheckRisk("org-1", budget.RiskHigh, 5.0)
// decision.Allowed       — within budget?
// decision.RiskCost      — weighted cost (5.0 * 5.0 = 25.0 for HIGH)
// decision.AutonomyShrunk — did autonomy decrease?
```

### Autonomy Shrinking

When uncertainty increases, autonomy automatically shrinks:

```go
enforcer.ShrinkAutonomy("org-1", 0.8)  // high uncertainty
// Autonomy drops proportionally
// CRITICAL actions blocked when autonomy < 100
// HIGH actions blocked when autonomy < 70
```

---

## Budget Enforcement

**Package:** `core/pkg/budget/enforcer.go`

Financial budget enforcement with fail-closed semantics and receipted audit trail.

### Design Principles

1. **Fail-closed:** Any error during budget check results in denial
2. **Atomic check-and-update:** Mutex-serialized for single-instance; PostgreSQL advisory locks for distributed
3. **Receipted:** Every budget decision produces an `EnforcementReceipt` with ID, tenant, action, cost, and reason

### Usage

```go
enforcer := budget.NewSimpleEnforcer(storage)

decision, err := enforcer.Check(ctx, "org-1", budget.Cost{
    AmountCents: 150,  // $1.50
    Action:      "llm-inference",
})

if !decision.Allowed {
    // Budget exceeded: decision.Reason explains why
}
```

### Budget Resets

- Daily budgets reset at midnight UTC
- Monthly budgets reset on the 1st
- Automatic boundary detection in Check()

---

## Temporal Guardian (Graded Response)

**Package:** `core/pkg/guardian/temporal.go`

The Temporal Guardian monitors agent effect frequency and escalates through a 5-level graded response ladder. This is HELM's analog to Microsoft's rate limiting, but with graduated response and automatic de-escalation.

### Response Levels

| Level | Threshold | Sustained For | Cooldown | Effect |
|---|---|---|---|---|
| **OBSERVE** | — | — | — | Monitor only, all effects pass |
| **THROTTLE** | 10 eff/s | 5s | 30s | Rate-limit; excess delayed |
| **INTERRUPT** | 50 eff/s | 3s | 60s | Pause action; require operator ack |
| **QUARANTINE** | 100 eff/s | 2s | 120s | Isolate agent; block all effects |
| **FAIL_CLOSED** | 200 eff/s | 1s | 300s | Emergency halt; no effects |

### How It Works

1. **ControllabilityEnvelope** tracks effect events in a sliding window (default 60s)
2. On each effect, `Evaluate()` calculates the current rate
3. If rate exceeds a threshold for the sustained duration, the level escalates
4. Effects are allowed only at OBSERVE and THROTTLE levels
5. De-escalation occurs when rate drops below threshold AND cooldown elapses

### Integration

The Temporal Guardian is wired into the Guardian pipeline as an intervention source:

```go
tg := guardian.NewTemporalGuardian(guardian.DefaultEscalationPolicy())
g := guardian.NewGuardian(signer, graph, nil,
    guardian.WithTemporalGuardian(tg),
)
```

When the Temporal Guardian reaches INTERRUPT or QUARANTINE, it overrides the normal PRG evaluation and forces `VerdictEscalate` with `ReasonTemporalIntervene`.

---

## Simulation Framework

**Package:** `core/pkg/simulation/`

HELM includes a simulation framework for testing governance policies and budget behavior under controlled scenarios.

### Scenario Types

| Type | Purpose |
|---|---|
| `BUDGET` | Spending projection and runway calculation |
| `STAFFING` | Headcount and capacity planning |
| `DP_REHEARSAL` | Decision process rehearsal |
| `STRESS` | Load testing and peak behavior |

### Defining Scenarios

```go
scenario := simulation.Scenario{
    Name: "budget-exhaustion-test",
    Steps: []simulation.ScenarioStep{
        {Action: "llm-inference", Actor: "agent-1", ExpectedDecision: "ALLOW"},
        {Action: "llm-inference", Actor: "agent-1", ExpectedDecision: "ALLOW"},
        {Action: "llm-inference", Actor: "agent-1", ExpectedDecision: "DENY"},  // budget exceeded
    },
}
```

### Running Simulations

```go
runner := simulation.NewRunner()
result := runner.Run(scenario)
// result.PassRate() — fraction of steps matching expectations
// result.Status     — PASSED, FAILED, etc.
```

---

## OpenTelemetry Integration

**Package:** `core/pkg/observability/observability.go`

HELM exports metrics and traces via OpenTelemetry (OTLP gRPC).

### RED Metrics

| Metric | Type | Description |
|---|---|---|
| `helm.requests.total` | Counter | Total governed requests |
| `helm.errors.total` | Counter | Total errors |
| `helm.request.duration` | Histogram | Request duration (buckets: 1ms-10s) |
| `helm.operations.active` | UpDownCounter | Currently active operations |

### Prometheus Endpoints

Expose at `:9090/metrics`:

| Metric | Labels |
|---|---|
| `helm_guardian_decisions_total` | `verdict` |
| `helm_guardian_decision_duration_seconds` | — |
| `helm_executor_tool_calls_total` | `tool_id`, `status` |
| `helm_proofgraph_nodes_total` | `type` |
| `helm_budget_remaining` | `tenant_id` |
| `helm_evidence_verification_total` | `result` |

### Alerting Rules

```yaml
# Alert when Guardian p99 exceeds 5ms
- alert: GuardianLatencyHigh
  expr: histogram_quantile(0.99, helm_guardian_decision_duration_seconds) > 0.005
  for: 5m

# Alert when error budget drops below 20%
- alert: BudgetExhausted
  expr: helm_budget_remaining < 20
  for: 1m
```

### Structured Logging

HELM uses `slog` with trace ID correlation:

```
level=INFO msg="decision" trace_id=abc123 decision_id=dec-xyz verdict=ALLOW latency_ms=48
```

---

## Chaos Testing

**Reference:** `docs/CHAOS_TESTING.md`

HELM includes 6 chaos testing scenarios:

1. **Error Budget Exhaustion** — Verify 429 responses when budget < 20%
2. **Signer Unavailable** — Guardian returns DENY on nil signer (fail-closed)
3. **Clock Drift** — Expired intents rejected despite clock manipulation
4. **Concurrent Storm** — 1000 concurrent tool calls with race detector
5. **Policy Graph Mutation** — In-flight decisions unaffected by PRG mutations
6. **Malformed Input** — Oversized payloads (>1MB) and invalid JSON rejected

Run with: `cd core && go test -race ./pkg/guardian/... ./pkg/budget/...`

---

## Tamper-Evident Audit Trail

**Package:** `core/pkg/guardian/audit.go`

Every governance decision is logged to a tamper-evident audit trail with SHA-256 hash chaining:

```go
type AuditEntry struct {
    ID           string    // Unique entry ID
    Timestamp    time.Time // Authority clock time
    Actor        string    // Principal who triggered the action
    Action       string    // What was attempted
    Target       string    // What was affected
    Details      string    // Canonical decision details
    PreviousHash string    // SHA-256 of previous entry (chain link)
    Hash         string    // SHA-256 of this entry
}
```

Chain integrity verification: `auditLog.VerifyChain()` validates that each entry's hash matches its content and links to the previous entry.

---

## Pack Telemetry & Trust Scoring

**Package:** `core/pkg/pack/telemetry.go`

HELM tracks operational telemetry per pack (governance template):

| Metric | Description |
|---|---|
| InstallCount | Total installations across the ecosystem |
| ActiveInstances | Currently running instances |
| FailureRate | % of executions with errors (30-day window) |
| EvidenceSuccessRate | % of successful evidence generation |
| IncidentRate | Incidents per 1K executions (30-day window) |
| MeanTimeToRecovery | MTTR in seconds |
| TrustScore | Computed reliability score (0.0-1.0) |
| ConfidenceScore | Statistical confidence based on sample size |

### Trust Score Calculation

```
score = 1.0
if failure_rate > threshold:    score *= 0.5
if evidence_success < target:   score *= 0.3
if incident_rate > limit:       score *= 0.5
```

### Confidence Score

| Install Count | Confidence |
|---|---|
| 1 | 0.001 |
| 100 | 0.1 |
| 1,000+ | 1.0 |

---

## SLO Engine — Governance-Driven SLO Enforcement

**Package:** `core/pkg/observability/slo_engine.go`

The SLO Engine extends basic SLO tracking with automatic governance actions. When SLO violations are detected, the engine triggers graduated responses — not just alerts.

### Governance Actions on SLO Breach

| SLO State | Burn Rate | Governance Action |
|---|---|---|
| Healthy | < 1.0 | None — normal operations |
| Warning | 1.0-3.0 | Log warning, emit CloudEvent |
| Degraded | 3.0-10.0 | Throttle: reduce allowed request rate by 50% |
| Critical | 10.0-50.0 | Escalate: require human approval for all elevated operations |
| Emergency | > 50.0 | Freeze: block all non-essential effects, emit circuit breaker |

### Configuration

```go
engine := observability.NewSLOEngine(observability.SLOEngineConfig{
    Tracker:           tracker,
    GovernanceActions: true,       // Enable automatic governance responses
    EscalateThreshold: 10.0,      // Burn rate triggers escalation
    FreezeThreshold:   50.0,      // Burn rate triggers freeze
    NotifySink:        cloudEventsExporter,
})
```

---

## Receipted Circuit Breakers

HELM's circuit breakers record every state transition as a ProofGraph node. This means auditors can verify exactly when a breaker tripped, why, and when it recovered.

### ProofGraph Integration

```go
breaker := resiliency.NewReceiptedCircuitBreaker(
    "guardian-backend",
    5,                    // failure threshold
    10 * time.Second,     // reset timeout
    proofGraph,           // ProofGraph for receipting
    signer,               // Ed25519 signer
)
```

Each state transition (CLOSED -> OPEN, OPEN -> HALF_OPEN, HALF_OPEN -> CLOSED/OPEN) produces a signed `TRUST_EVENT` node in the ProofGraph with:
- Breaker name, old state, new state
- Failure count, last error summary
- Timestamp (Lamport-ordered)
- Ed25519 signature

---

## Cost Estimation for SRE Planning

**Package:** `core/pkg/budget/cost_attribution.go`

SRE teams can use cost estimation to project agent spend and set budget alerts:

### Pre-Execution Cost Estimation

```go
estimate, err := budget.EstimateCost(ctx, budget.CostEstimateRequest{
    Tool:       "llm-inference",
    Parameters: map[string]any{"model": "claude-sonnet", "max_tokens": 4096},
    TenantID:   "org-1",
})
// estimate.AmountCents  — projected cost
// estimate.Confidence   — estimation confidence (0.0-1.0)
// estimate.Model        — estimation model used (token_count, fixed, api_price)
```

### Cost Attribution Dashboard Metrics

| Metric | Type | Labels |
|---|---|---|
| `helm_cost_estimated_cents` | Histogram | `tenant_id`, `tool_id`, `model` |
| `helm_cost_actual_cents` | Histogram | `tenant_id`, `tool_id`, `model` |
| `helm_cost_overrun_ratio` | Gauge | `tenant_id` |
| `helm_budget_burn_rate` | Gauge | `tenant_id` |

---

## Ensemble Threat Scanner Operations

**Package:** `core/pkg/threatscan/ensemble.go`

The ensemble scanner runs multiple independent threat detection engines and uses quorum-based verdicts to prevent single-scanner bypass.

### Scanner Health Monitoring

| Metric | Description |
|---|---|
| `helm_scanner_health{scanner="prompt_injection"}` | Scanner availability (1=healthy, 0=down) |
| `helm_scanner_latency{scanner="..."}` | Per-scanner evaluation latency |
| `helm_scanner_detections{scanner="..."}` | Detection count per scanner |
| `helm_ensemble_quorum_failures` | Requests where quorum could not be reached (insufficient scanners) |

### Operational Behavior

- If a scanner is unavailable, the ensemble **fails closed** — insufficient quorum triggers `DENY`
- Scanner timeouts are configurable per engine (default: 100ms)
- Scanners run in parallel; total ensemble latency is bounded by the slowest scanner + quorum evaluation

### MCPTox Scanner

The MCPTox scanner detects MCP-specific supply chain threats:

| Detection | Description |
|---|---|
| **Rug-pull** | Tool behavior changed after initial approval (schema hash drift) |
| **Typosquatting** | Tool name is suspiciously similar to a known tool (Levenshtein distance < 2) |
| **Supply chain** | Tool package dependencies include known-malicious or recently-transferred packages |

---

## Comparison with Microsoft Agent SRE

| Capability | Microsoft AGT | HELM | Notes |
|---|---|---|---|
| SLO tracking | Error budget + burn rate | Error budget + burn rate + p99 tracking | Equivalent |
| Circuit breakers | 3-state machine | 3-state + exponential backoff + W3C tracing | HELM adds trace propagation |
| Graded response | Static rate limiting | 5-level escalation ladder with auto de-escalation | **HELM advantage** |
| Risk budgets | Not documented | Risk-weighted limits + autonomy shrinking + blast radius caps | **HELM advantage** |
| Chaos testing | Fault injection framework | 6 deterministic chaos scenarios | Equivalent |
| Audit trail | Append-only log | SHA-256 hash-chained, tamper-evident | **HELM advantage** |
| Simulation | Not documented | Budget/staffing/stress scenario framework | **HELM advantage** |
| Pack telemetry | Not documented | Trust scoring + MTTR + confidence | **HELM advantage** |
| SLO-driven governance | SLO alerting only | SLO violations trigger governance actions (throttle/freeze) | **HELM advantage** |
| Receipted breakers | Not documented | Circuit breaker transitions receipted in ProofGraph | **HELM advantage** |
| Cost estimation | Not documented | Pre-execution cost estimation with confidence scoring | **HELM advantage** |
| Ensemble scanning | Single scanner | Quorum-based multi-engine with fail-closed on unavailability | **HELM advantage** |
| MCPTox detection | Not documented | Rug-pull, typosquatting, supply chain attack detection | **HELM advantage** |
| CloudEvents SIEM | Not documented | Governance decisions as CloudEvents for SIEM ingestion | **HELM advantage** |
