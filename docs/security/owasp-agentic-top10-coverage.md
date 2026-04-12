# HELM vs OWASP Agentic Top 10 Coverage Matrix

Generated: 2026-04-12
HELM Version: 0.3.0
Guardian Pipeline: 6-gate + output quarantine

## Coverage Summary

| # | OWASP Agentic Risk | Coverage | Guardian Gates | Conformance Proof |
|---|-------------------|----------|---------------|-------------------|
| 1 | Prompt Injection | FULL | Threat, Context | `threatscan/` scanner, `SourceChannelDirectInput` |
| 2 | Tool Poisoning | FULL | Egress, Threat, Freeze | `firewall/` fail-closed allowlist, `owasp_threat_vectors.json` UC-013 |
| 3 | Excessive Permission Scope | FULL | Delegation, Identity | Effect class ceilings (E1-E4), blast radius checks, UC-019 |
| 4 | Insufficient Permission Validation | FULL | Identity, Delegation | P0/P1/P2 policy layers, CPI verdict enforcement, UC-020 |
| 5 | Improper Output Handling | FULL | Output Quarantine | `Guardian.EvaluateOutput()`, `SourceChannelToolOutput` scanning |
| 6 | Resource Overborrowing | FULL | Context, Delegation | Budget gate (`budget/`), spend ceilings, token limits, UC-017 |
| 7 | Uncontrolled Cascading Effects | FULL | Delegation, Freeze | Delegation depth limits, proofgraph causal DAG, circuit breaker |
| 8 | Sensitive Data Exposure | FULL | Egress, Context | Egress firewall (fail-closed), data classification caps, selective disclosure JWT |
| 9 | Insecure Plugin/Tool Integration | FULL | Threat, Egress | MCP governance interceptor, connector policy, mTLS, tool schema validation |
| 10 | Insufficient Monitoring/Logging | FULL | All gates | Evidence packs (JCS+SHA-256), proofgraph, OTel integration, receipt chain |

**Result: 10/10 FULL coverage**

## Detailed Mapping

### 1. Prompt Injection

**Risk:** Adversarial inputs manipulate agent behavior through crafted prompts.

**HELM Coverage:**
- `core/pkg/threatscan/` — Threat scanner with multiple detection strategies
- Guardian Gate 5 (Threat) — Scans all inputs before execution
- `SourceChannelDirectInput` classification for user-provided content
- `conform/adversarial/threat_scenarios.go` — Adversarial scenario test suite
- P1 policy bundles can define injection detection rules (CEL expressions)

**Conformance Vectors:** `owasp_threat_vectors.json` — injection patterns tested

### 2. Tool Poisoning

**Risk:** Malicious tool definitions or modified tool behaviors compromise agent.

**HELM Coverage:**
- `core/pkg/firewall/` — Network egress firewall (fail-closed: empty allowlist = deny-all)
- Guardian Gate 4 (Egress) — All outbound connections gated
- Tool schema validation in MCP gateway (`core/pkg/mcp/gateway.go`)
- Effect class ceilings prevent E4 (irreversible) by default
- `owasp_threat_vectors.json` UC-013 tests `exec_shell` with `curl | bash`

### 3. Excessive Permission Scope

**Risk:** Agent granted more permissions than needed for its task.

**HELM Coverage:**
- Guardian Gate 6 (Delegation) — Scope narrowing per session
- P2 overlays — Per-session permission narrowing (never widening)
- Blast radius checks — `system_wide` scope denied for restricted envelopes
- `core/pkg/effects/` — EffectPermit binds verdict to specific connector/action/scope
- UC-019 tests system-wide blast radius denial

### 4. Insufficient Permission Validation

**Risk:** Tool calls proceed without proper authorization checks.

**HELM Coverage:**
- Guardian Gate 3 (Identity) — Identity verification before execution
- Three-layer policy: P0 ceilings → P1 bundles → P2 overlays
- CPI verdict: ALLOW | DENY | REQUIRE_APPROVAL (fail-closed)
- `core/pkg/guardian/` — TLA+-verified 6-gate pipeline (`proofs/GuardianPipeline.tla`)
- Data classification enforcement — UC-020 tests restricted data denial

### 5. Improper Output Handling

**Risk:** Agent outputs contain malicious content, PII leakage, or hallucinations.

**HELM Coverage:**
- `Guardian.EvaluateOutput()` — Output quarantine gate (added 2026-04)
- `SourceChannelToolOutput` — Dedicated scanner channel for tool outputs
- Quarantine on high-risk findings, logged to audit trail
- Threat scanner reused for output scanning (same detection strategies)

### 6. Resource Overborrowing

**Risk:** Agent consumes excessive resources (compute, API calls, budget).

**HELM Coverage:**
- `core/pkg/budget/` — Budget gate with spend ceilings
- Token consumption tracking per session
- Rate limiting in MCP gateway
- P0 ceilings define absolute resource limits
- UC-017 tests resource overborrowing denial

### 7. Uncontrolled Cascading Effects

**Risk:** Agent actions trigger uncontrolled chain reactions across systems.

**HELM Coverage:**
- Delegation depth limits (configurable, default: 3)
- `core/pkg/proofgraph/` — Causal DAG with Lamport ordering tracks all effects
- Circuit breaker patterns — Guardian Gate 1 (Freeze) halts cascading failures
- `core/pkg/mama/` — Multi-agent runtime with lane-based concurrency isolation

### 8. Sensitive Data Exposure

**Risk:** Agent leaks sensitive data through tool calls or outputs.

**HELM Coverage:**
- Guardian Gate 4 (Egress) — All outbound data gated
- `core/pkg/firewall/` — Fail-closed egress control
- Data classification levels in policy bundles
- Selective disclosure JWT (`core/pkg/crypto/`) — Field-level access control
- `core/pkg/compliance/gdpr/` — GDPR data subject rights enforcement

### 9. Insecure Plugin/Tool Integration

**Risk:** Third-party tools/plugins introduce vulnerabilities.

**HELM Coverage:**
- MCP governance interceptor (`core/pkg/mcp/gateway.go`)
- Connector policy enforcement (`core/pkg/connectors/`)
- mTLS for service-to-service communication (`core/pkg/crypto/`)
- Tool schema validation before execution
- `core/pkg/runtimeadapters/` — Universal adapter interface with governance

### 10. Insufficient Monitoring/Logging

**Risk:** Lack of visibility into agent actions prevents detection of compromises.

**HELM Coverage:**
- Evidence packs (`core/pkg/evidencepack/`) — JCS-canonicalized, SHA-256 hashed
- Proofgraph (`core/pkg/proofgraph/`) — Complete causal audit trail
- OpenTelemetry integration for metrics and traces
- Receipt chain — Every decision produces a tamper-evident receipt
- `make bench-report` — Performance and overhead monitoring

## Latency Comparison

| Component | HELM p99 | Microsoft AGT Target |
|-----------|---------|---------------------|
| Guardian Pipeline (6-gate) | < 100us | < 100us |
| Threat Scanner | < 500us | N/A |
| Evidence Pack Hash | < 50us | N/A |
| Output Quarantine | < 200us | N/A |

Run `make bench` to reproduce. Results at `benchmarks/results/latest.json`.

## Conformance Verification

```bash
# Run OWASP conformance vectors
make test-owasp

# Full conformance (includes OWASP)
make crucible-full

# Benchmark Guardian latency
make bench-report
```
