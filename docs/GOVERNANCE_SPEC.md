---
title: GOVERNANCE_SPEC
---

# HELM Governance Subsystem Specification

> Normative reference for the governance subsystem in `core/pkg/governance/`.
> This documents behavior that previously existed only as Go code.
>
> **Canonical architecture**: see [ARCHITECTURE.md](ARCHITECTURE.md) for the
> system-level model (VGL, VPL, Policy Precedence).

## 1. Policy Decision Point (PDP)

### 1.1 Interface Contract

The PDP is the central policy evaluation surface. Any policy backend
MUST implement:

```
Evaluate(ctx, PDPRequest) → PDPResponse | error
PolicyVersion() → string
```

**Fail-closed guarantees:**

- PDP errors MUST result in `DENY` with reason code `PDP_ERROR`
- PDP denials MUST include a `ReasonCode` and `PolicyRef`
- All PDP outcomes are bound into the `DecisionRecord` via `PolicyDecisionHash`

### 1.2 Request/Response Types

| Field                           | Type         | Description                                                                              |
| ------------------------------- | ------------ | ---------------------------------------------------------------------------------------- |
| `PDPRequest.EffectDescriptor`   | struct       | Effect type, parameters, estimated cost                                                  |
| `PDPRequest.SubjectDescriptor`  | struct       | Principal, tenant, roles                                                                 |
| `PDPRequest.AuthContext`        | struct       | Token, claims, authentication method                                                     |
| `PDPRequest.ContextDescriptor`  | struct       | Environment, jurisdiction, time window                                                   |
| `PDPRequest.ObligationsContext` | struct       | Pending obligations from prior decisions                                                 |
| `PDPResponse.Allow`             | bool         | Whether the effect is permitted                                                          |
| `PDPResponse.ReasonCode`        | string       | Machine-readable reason (see `protocols/json-schemas/reason-codes/reason-codes-v1.json`) |
| `PDPResponse.Obligations`       | []Obligation | Post-decision obligations                                                                |
| `PDPResponse.DecisionHash`      | string       | Content-addressed hash of the decision                                                   |

### 1.3 Policy Backends

| Backend        | File                      | Status      |
| -------------- | ------------------------- | ----------- |
| CEL            | `policy_evaluator_cel.go` | Implemented |
| PRG (built-in) | `engine.go` via `prg/`    | Implemented |

---

## 2. Verdict and Reason Code Registry

Canonical source: [`contracts/verdict.go`](../core/pkg/contracts/verdict.go)

| Verdict    | Meaning                                  |
| ---------- | ---------------------------------------- |
| `ALLOW`    | Effect is permitted                      |
| `DENY`     | Effect is refused, DenialReceipt emitted |
| `ESCALATE` | Effect requires human/ceremony review    |

Reason codes: see the canonical registry in `protocols/json-schemas/reason-codes/reason-codes-v1.json`.

---

## 3. Denial Receipt System

Source: [`denial.go`](../core/pkg/governance/denial.go)

Every refusal produces a `DenialReceipt` — there are no silent drops.

| DenialReason   | Gate                                 |
| -------------- | ------------------------------------ |
| `POLICY`       | PRG / PDP rule violation             |
| `PROVENANCE`   | Artifact provenance check failed     |
| `BUDGET`       | Financial or rate limit exceeded     |
| `SANDBOX`      | Sandbox boundary violation           |
| `TENANT`       | Multi-tenant isolation breach        |
| `JURISDICTION` | Jurisdictional constraint violated   |
| `VERIFICATION` | Cryptographic verification failed    |
| `ENVELOPE`     | Effect envelope structurally invalid |

---

## 4. Jurisdiction Resolution

Source: [`jurisdiction.go`](../core/pkg/governance/jurisdiction.go)

### 4.1 Resolution Algorithm

1. Collect all `JurisdictionRule` entries matching the `serviceRegion`
2. Detect conflicts between rules with different `LegalRegime` values
3. **Priority-based resolution**: select the highest-priority rules
4. If highest-priority rules have a single regime → use that regime
5. If highest-priority rules conflict → set `LegalRegime = ""` (forces ESCALATE)
6. All conflicts are preserved in `JurisdictionContext.Conflicts` for audit

### 4.2 Rule Priority

Rules have a `Priority` field (integer, higher wins, default 0). Rules at
the same priority with different regimes create an unresolvable conflict
that MUST be escalated to human review.

---

## 5. Risk Envelope

Source: [`risk_envelope.go`](../core/pkg/governance/risk_envelope.go)

Every effect carries a risk envelope classifying its risk profile. The envelope
contains risk dimensions (data sensitivity, reversibility, blast radius, etc.)
that feed into the PDP for risk-proportionate policy evaluation.

---

## 6. Governance Lifecycle

Source: [`lifecycle.go`](../core/pkg/governance/lifecycle.go)

Governance decisions follow a lifecycle: `PENDING → EVALUATING → DECIDED → EXECUTED → COMPLETED`.
Each transition produces a ProofGraph node.

---

## 7. Supporting Subsystems

| Subsystem           | File                     | Purpose                             |
| ------------------- | ------------------------ | ----------------------------------- |
| Advisor             | `advisor.go`             | Governance recommendations          |
| Canary              | `canary.go`              | Canary deployment policy            |
| Corroborator        | `corroborator.go`        | Multi-source decision corroboration |
| Data Classification | `data_classification.go` | Data sensitivity classification     |
| Liveness            | `liveness.go`            | Governance health probes            |
| Policy Inductor     | `policy_inductor.go`     | Learning policy refinements         |
| Power Delta         | `power_delta.go`         | Permission change analysis          |
| Security            | `security.go`            | Security hardening checks           |
| Self-Modification   | `self_mod.go`            | Agent self-modification detection   |
| Signal Controller   | `signal_controller.go`   | Control signal routing              |
| State Estimator     | `state_estimator.go`     | Governance state estimation         |
| Swarm PDP           | `swarm_pdp.go`           | Multi-agent PDP coordination        |

---

## 8. Path-Aware Policy Evaluation

The PDP supports **path-aware policies** — policies that consider the full session history (prior decisions, tool calls, and trust score changes) when evaluating a new request.

**Session history** is passed via `PDPRequest.ContextDescriptor.SessionHistory`, which contains an ordered list of prior `DecisionRecord` hashes. Policies can express constraints such as:

- "Allow `file_write` only if a preceding `file_read` in the same session returned data from the same path"
- "Deny `http_post` if `http_get` to an untrusted domain occurred earlier in the session"
- "Escalate if more than 5 ALLOW decisions have been issued in the current session without a human checkpoint"

Path-aware evaluation is implemented via CEL macros that traverse the session history:

```
session.prior_decisions.exists(d, d.tool == "file_read" && d.target == request.target)
```

---

## 9. Ensemble Threat Scanning

Source: [`threatscan/ensemble.go`](../core/pkg/threatscan/ensemble.go)

The governance pipeline supports **ensemble scanning** — multiple independent threat scanners run in parallel on every request, and a quorum-based verdict determines the outcome.

| Scanner | Detection Target |
|---|---|
| Prompt injection | Direct/indirect injection attempts |
| Data exfiltration | Sensitive data leakage via tool output |
| PII detector | Personal information in inputs/outputs |
| Toxicity classifier | Harmful or abusive content |
| MCPTox | Rug-pull, typosquatting, supply chain attacks in MCP tool registries |

**Quorum policy:** Configurable via `threat_scan.quorum` in the policy bundle. Default: any single scanner flagging triggers `ESCALATE`; two or more scanners flagging triggers `DENY`.

---

## 10. Memory Governance

Source: [`memory/`](../core/pkg/memory/)

Agent memory (context, conversation history, learned state) is subject to governance:

- **Integrity verification**: Memory snapshots are content-addressed (SHA-256). Any mutation outside governed operations is detected.
- **Trust scoring**: Memory entries carry trust scores derived from the provenance of the data that produced them.
- **Cross-session poisoning prevention**: Memory imported from prior sessions is re-evaluated against current policy before use.
- **Selective disclosure**: Memory can be exported with redaction (via ZK proofs) for compliance without revealing sensitive content.

---

## 11. Cost Attribution

Source: [`budget/cost_attribution.go`](../core/pkg/budget/cost_attribution.go)

Every governance decision carries a **cost attribution record**:

- **Pre-execution estimation**: The PDP includes estimated cost in the `PDPResponse` before the effect executes, allowing budget enforcement to reject actions that would exceed limits.
- **Post-execution attribution**: Actual cost is recorded and attributed to the specific agent, session, tenant, tool, and decision.
- **Cost dimensions**: LLM token cost, compute time, external API calls, storage, network egress.
- **Aggregation**: Cost rolls up through the tenant hierarchy for organizational budgeting.
