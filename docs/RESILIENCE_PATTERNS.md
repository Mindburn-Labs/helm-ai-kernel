---
title: Resilience Patterns
---

# HELM Resilience Patterns

HELM implements defense-in-depth reliability through layered resilience patterns. Each pattern is independently useful and composes with others for production-grade governance.

## Pattern 1: Fail-Closed Enforcement

**Principle:** When in doubt, deny. Every error, timeout, or uncertain state results in a denial with a receipted reason code.

**Implementation:**
- Guardian pipeline: 6 sequential gates, each fail-closed
- Budget enforcement: Storage errors produce denials (`SimpleEnforcer.Check`)
- Egress firewall: Empty allowlist = deny-all
- Policy evaluation: Unknown actions = `NO_POLICY_DEFINED` denial
- Agent kill switch: Lock-free `IsKilled()` check before any policy evaluation

**Impact:** No governance bypass is possible through error injection.

## Pattern 2: Circuit Breaking

**Package:** `core/pkg/util/resiliency/client.go`

Three-state circuit breaker protects downstream dependencies:

```
CLOSED (normal) ──> OPEN (failure threshold reached) ──> HALF_OPEN (recovery probe)
```

- **Failure threshold:** 5 consecutive failures (configurable)
- **Reset timeout:** 10 seconds (configurable)
- **Half-open:** Allows 1 probe request; success closes, failure re-opens
- **Overhead:** Sub-microsecond state check

## Pattern 3: Exponential Backoff with Jitter

Built into `EnhancedClient`:

```
delay = base * 2^attempt + random(0, 50ms)
```

- **Max retries:** 3 (configurable)
- **Jitter range:** 0-50ms (prevents thundering herd)
- **4xx responses:** Not retried (client error, not transient)
- **5xx responses:** Retried with backoff

## Pattern 4: Risk-Weighted Budget Limits

**Package:** `core/pkg/budget/risk_budget.go`

Actions consume risk budget proportional to their risk level:

| Risk | Multiplier | Autonomy Required |
|---|---|---|
| LOW | 1x | >= 10 |
| MEDIUM | 2x | >= 40 |
| HIGH | 5x | >= 70 |
| CRITICAL | 10x | Impossible (never autonomous) |

Three independent budget dimensions:
1. **Compute cap** — Maximum execution time (ms)
2. **Blast radius cap** — Maximum affected resources
3. **Risk score cap** — Aggregate weighted risk

### Autonomy Shrinking

When uncertainty increases, autonomy level decreases proportionally. This progressively blocks higher-risk actions without a binary on/off switch:

```
Autonomy 80 → uncertainty rises to 0.8 → autonomy shrinks to 16
→ only LOW-risk actions remain autonomous
```

## Pattern 5: Graded Response (Temporal Guardian)

**Package:** `core/pkg/guardian/temporal.go`

Five-level graduated response based on effect rate, with automatic escalation and de-escalation. See [Incident Response Guide](./INCIDENT_RESPONSE.md) for details.

Unlike binary rate limiting, the graded response provides proportional enforcement: throttling before interrupting, interrupting before quarantining, quarantining before emergency halt.

## Pattern 6: Tamper-Evident Audit Chain

**Package:** `core/pkg/guardian/audit.go`

Every governance decision is appended to a hash-chained audit log:

```
Entry[n].Hash = SHA-256(Entry[n].Content)
Entry[n].PreviousHash = Entry[n-1].Hash
```

Chain integrity can be verified at any time with `VerifyChain()`. Any tampering breaks the hash chain and is immediately detectable.

## Pattern 7: Deterministic Canonicalization

**Package:** `core/pkg/kernel/csnf.go`, `core/pkg/canonicalize/jcs.go`

All governance data structures are canonicalized before signing or hashing:

- **JCS (RFC 8785):** JSON Canonicalization Scheme for cross-platform determinism
- **CSNF v1:** Canonical Semantic Normal Form with NFC Unicode normalization, integer-only numbers, deterministic array sorting

Same input produces byte-identical output on any platform, any architecture, any language.

## Pattern 8: Nondeterminism Bounding

**Package:** `core/pkg/kernel/nondeterminism.go`

LLM outputs, external API calls, and random values are explicitly bounded and receipted:

```go
tracker.Capture(runID, NDSourceLLM, "gpt-4 completion", inputHash, outputHash, seed)
receipt, _ := tracker.Receipt(runID)
```

The `NondeterminismReceipt` captures the exact input/output hashes of each nondeterministic operation, enabling post-hoc verification that governance was applied to the actual data.

## Pattern 9: Per-Connector Circuit Breakers

> *Added April 2026*

**Package:** `core/pkg/effects/circuitbreaker.go`

Each connector gets an independent circuit breaker instance, isolating failures to the affected connector without degrading others.

```
Connector A: CLOSED (healthy)
Connector B: OPEN (5 failures, waiting for reset)
Connector C: HALF_OPEN (probing recovery)
```

- **Per-connector isolation:** One failing connector does not trip breakers on unrelated connectors
- **State is receipted:** Circuit breaker state transitions are recorded in the ProofGraph
- **Composable with reversibility:** IRREVERSIBLE effects are blocked when the circuit is OPEN; REVERSIBLE effects may proceed with elevated monitoring

## Pattern 10: SLO Engine

**Package:** `core/pkg/slo/engine.go`

Service Level Objectives with error budget tracking:

- **Latency SLOs** — p50/p99 latency targets per tool or connector
- **Error-rate SLOs** — maximum failure percentage over a sliding window
- **Budget burn** — tracks remaining error budget as a 0.0-1.0 gauge
- **Automatic response** — when budget < threshold, the engine can restrict new executions to low-risk-only or trigger alerts

SLO violations are surfaced as Prometheus metrics (`helm.slo.violations`) and OTel attributes on decision spans.

## Pattern 11: Ensemble Threat Scanning

**Package:** `core/pkg/threatscan/ensemble.go`

Multiple threat scanners run in parallel with configurable voting:

| Strategy | Behavior | Use Case |
|----------|----------|----------|
| **ANY** | Flag if any scanner detects | High-security environments |
| **MAJORITY** | Flag if >50% agree | Balanced (default) |
| **UNANIMOUS** | Flag only if all agree | Low false-positive tolerance |

Each scanner result is individually receipted, enabling post-hoc analysis of which scanners flagged which threats. The ensemble eliminates single-scanner blind spots.

## Pattern 12: Pre-Execution Cost Estimation

**Package:** `core/pkg/budget/estimate.go`

Before an effect executes, the cost estimator predicts the cost based on:

- **Connector pricing model** — API call costs, token counts, compute time
- **Historical data** — moving average of actual costs for similar operations
- **Risk multiplier** — higher-risk effects carry a cost premium

The estimate is attached to the `CostBreakdown` field in `effects/types.go` and surfaced in the ProofGraph for per-agent cost attribution. Budget gates can deny effects whose estimated cost exceeds remaining budget.

## Composition

These patterns layer for defense-in-depth:

```
Request → Kill Switch (Pattern 1) → Ensemble Scan (Pattern 11)
       → Circuit Breaker (Pattern 2/9) → Cost Estimation (Pattern 12)
       → Temporal Guardian (Pattern 5) → Risk Budget (Pattern 4)
       → SLO Check (Pattern 10) → Policy Evaluation (Pattern 1)
       → Signing (Pattern 7) → Audit Chain (Pattern 6)
       → Nondeterminism Receipt (Pattern 8)
```

Each layer is independently fail-safe. Removing any single layer does not compromise the others.
