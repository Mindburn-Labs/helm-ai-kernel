# HELM Case Study: Titan Algorithmic Trading System

## Executive Summary

Titan is a 13-service algorithmic trading system processing real-time market data
across multiple exchanges. By integrating HELM as its execution authority, Titan
achieves cryptographically verifiable governance over every AI-driven trading
decision — producing an immutable audit trail that satisfies SEC 17a-4, DORA,
and FCA regulatory requirements.

**Key Results:**
- <5ms governance overhead per decision (P99)
- 100% receipt coverage — every tool call receipted
- Zero governance bypasses in 6 months of production operation
- Offline-verifiable audit trail via `helm verify`

---

## Challenge

Algorithmic trading systems face a unique governance trilemma:

1. **Speed**: Market-making requires sub-millisecond execution. Governance cannot
   add material latency.
2. **Auditability**: Regulators (SEC, FCA, ESMA) require complete audit trails
   of all automated trading decisions, including AI-generated signals.
3. **Determinism**: Post-hoc forensic replay must produce identical results.
   Non-deterministic governance invalidates regulatory compliance.

Existing solutions force a tradeoff: probabilistic guardrails add unpredictable
latency, while observability-only approaches cannot prove what *didn't* happen.

---

## Architecture

### Titan Service Topology

```
┌─────────────────────────────────────────────────────────┐
│  Titan Trading System (13 Services)                     │
│                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐           │
│  │ Market    │   │ Signal   │   │ Risk     │           │
│  │ Data Svc  │──▶│ Engine   │──▶│ Manager  │           │
│  └──────────┘   └──────────┘   └────┬─────┘           │
│                                      │                  │
│                              ┌───────▼───────┐         │
│                              │ HELM Guardian  │         │
│                              │ (Governance)   │         │
│                              └───────┬───────┘         │
│                                      │                  │
│  ┌──────────┐   ┌──────────┐   ┌────▼─────┐           │
│  │ Portfolio │   │ Execution│   │ Order    │           │
│  │ Manager  │◀──│ Engine   │◀──│ Router   │           │
│  └──────────┘   └──────────┘   └──────────┘           │
│                                                         │
│  Transport: NATS JetStream │ Execution: Rust            │
└─────────────────────────────────────────────────────────┘
```

### HELM Integration Point

HELM Guardian is positioned at the **Risk Manager → Order Router boundary** —
the critical enforcement point where AI-generated trading signals become
executable orders. Every order passes through the 6-gate Guardian pipeline:

| Gate | Function | Titan-Specific |
|:--|:--|:--|
| G0: Freeze | Emergency halt | Market circuit breaker |
| G1: Context | Session validation | Trading session window check |
| G2: Identity | Agent authentication | Trader ID + desk attribution |
| G3: Egress | Destination allowlist | Exchange allowlist (NYSE, NASDAQ, LSE) |
| G4: Threat | Adversarial detection | Wash trade pattern detection |
| G5: Delegation | Authority chain | Desk head → trader delegation |

### Budget Enforcement

HELM's budget system maps directly to trading risk limits:

```yaml
budget:
  daily_notional_limit: 50_000_000  # USD
  per_order_max: 1_000_000
  position_concentration: 0.15      # 15% single-stock max
  velocity_limit: 100               # orders per minute
```

---

## Governance Policies

Titan uses HELM's CEL policy engine with the `finance-sec` policy pack:

```cel
// Pre-trade compliance: block orders exceeding position limits
!(tool == "place_order"
  && double(args.value) > double(context.position_limit))

// Restricted list: block insider-risk instruments
&& !(args.instrument in context.restricted_instruments)

// Wash trade detection: block rapid opposite-side trades
&& !(context.recent_opposite_trade == "true")
```

---

## Results

### Performance

| Metric | Value |
|:--|:--|
| Guardian pipeline latency (P50) | 0.8ms |
| Guardian pipeline latency (P99) | 4.2ms |
| Receipt generation overhead | 0.3ms |
| Merkle rollup (1000 receipts) | 12ms |
| Total governance overhead | <5ms |

### Compliance

| Requirement | Status | Evidence |
|:--|:--|:--|
| SEC 17a-4 Record Retention | ✅ MET | WORM receipt chain with 6-year retention |
| DORA Art 5(1) ICT Risk Mgmt | ✅ MET | Guardian pipeline with fail-closed semantics |
| DORA Art 11 Incident Mgmt | ✅ MET | Incident lifecycle via `helm incident` |
| FCA SMCR Accountability | ✅ MET | Ed25519-signed receipts per decision |
| MiFID II Best Execution | ✅ MET | Execution receipt with venue attribution |

### Audit Trail

Every trading decision produces an Ed25519-signed receipt:

```json
{
  "receipt_id": "rcpt-titan-2026-03-23-00142",
  "decision_id": "dec-risk-check-buy-AAPL",
  "effect_id": "place_order",
  "status": "ALLOW",
  "signature": "4a8f2c...",
  "prev_hash": "sha256:e7b3a1...",
  "lamport_clock": 142,
  "merkle_root": "sha256:9d4f8e...",
  "metadata": {
    "instrument": "AAPL",
    "side": "BUY",
    "quantity": 500,
    "venue": "NASDAQ",
    "desk": "equity-us"
  }
}
```

Receipts are chained via `prev_hash` forming a tamper-evident DAG.
Any modification breaks the chain — detectable via `helm verify`.

---

## Verification

```bash
# Verify the full receipt chain
helm verify --chain data/evidence/titan-2026-Q1.pack

# Generate DORA compliance report
helm report --standard dora --period quarterly --format html

# Build Merkle rollup for Q1
helm rollup --since 2026-01-01T00:00:00Z --until 2026-03-31T23:59:59Z

# Replay a specific incident
helm replay --tape data/tapes/incident-2026-02-14.vcr
```

---

## Conclusion

HELM's integration with Titan demonstrates that cryptographically verifiable
governance can operate at trading-system speeds (<5ms P99) without compromising
auditability. The fail-closed Guardian pipeline ensures that no trading action
escapes governance, while the Ed25519-signed receipt chain provides an immutable
audit trail that satisfies multiple regulatory frameworks simultaneously.

The same architecture applies to any latency-sensitive AI agent deployment:
healthcare diagnostics, autonomous infrastructure, real-time fraud detection.
