---
title: Simulation Guide
---

# HELM Simulation Guide

HELM includes a simulation framework for testing governance policies, budget behavior, and operational scenarios under controlled conditions before production deployment.

## Overview

**Package:** `core/pkg/simulation/`

The simulation framework enables:
- Pre-deployment policy validation
- Budget exhaustion modeling
- Capacity planning
- Stress testing of governance pathways
- Deterministic replay for incident reproduction

## Scenario Types

| Type | Purpose | Use Case |
|---|---|---|
| `BUDGET` | Spending projection | "Will our budget last 30 days at current rate?" |
| `STAFFING` | Capacity planning | "Do we have enough agents for peak load?" |
| `DP_REHEARSAL` | Decision process rehearsal | "Does this policy handle edge cases correctly?" |
| `STRESS` | Load testing | "What happens under 10x normal traffic?" |

## Defining Scenarios

### Policy Validation

Test that governance policies produce expected decisions:

```go
scenario := simulation.Scenario{
    Name:   "pii-protection-test",
    Status: simulation.StatusReady,
    Steps: []simulation.ScenarioStep{
        {
            Action:           "SEND_EMAIL",
            Actor:            "customer-agent",
            Context:          map[string]any{"contains_pii": true},
            ExpectedDecision: "DENY",
        },
        {
            Action:           "SEND_EMAIL",
            Actor:            "customer-agent",
            Context:          map[string]any{"contains_pii": false},
            ExpectedDecision: "ALLOW",
        },
    },
    Assertions: []simulation.ScenarioAssertion{
        {Field: "pass_rate", Operator: "eq", Value: "1.0"},
    },
}
```

### Budget Simulation

Project budget consumption under various patterns:

```go
runner := simulation.NewRunner()

// Configure budget simulation
sim := simulation.SimRun{
    SimType: simulation.SimBudget,
    Config: map[string]any{
        "daily_limit_cents":  10000,    // $100/day
        "avg_cost_per_call":  5,        // $0.05/call
        "calls_per_hour":     500,
        "projection_days":    30,
    },
}

result := runner.RunBudget(sim)
// result.BurnRate     — projected daily spend rate
// result.RunwayDays   — days until budget exhaustion
// result.Projections  — day-by-day forecast
```

### Stress Testing

Simulate high-concurrency governance loads:

```go
sim := simulation.SimRun{
    SimType: simulation.SimStress,
    Config: map[string]any{
        "concurrent_agents": 1000,
        "requests_per_agent": 100,
        "ramp_up_seconds":   10,
    },
}
```

## Running Simulations

```go
runner := simulation.NewRunner()

// Execute scenario
runner.Run(scenario)

// Check results
fmt.Printf("Pass rate: %.1f%%\n", scenario.PassRate()*100)
fmt.Printf("Status: %s\n", scenario.Status)
```

### CLI

```bash
helm simulate --scenario policy-test.yaml
helm simulate --type budget --daily-limit 10000 --calls-per-hour 500
helm simulate --type stress --agents 1000
```

## Deterministic Replay

Simulations use deterministic clocks and seeded PRNGs, enabling exact replay:

1. Record a live session's decisions and timing
2. Feed the recorded events into a simulation scenario
3. Verify the same policies produce the same outcomes
4. Detect policy regressions or behavior drift

## Integration with SRE

Simulation results feed into the SRE stack:

- **SLO validation:** Verify policies meet latency and success rate targets under load
- **Error budget projection:** Estimate when budget will exhaust under proposed policies
- **Capacity planning:** Determine required infrastructure for target throughput
- **Chaos rehearsal:** Pre-test incident response before running live chaos experiments

## Best Practices

1. **Run policy simulations on every PR** — Catch governance regressions before merge
2. **Budget projections monthly** — Track spend trends and adjust limits proactively
3. **Stress test before scale events** — Validate capacity before expected traffic spikes
4. **Replay production incidents** — Convert incident data into simulation scenarios for regression testing
