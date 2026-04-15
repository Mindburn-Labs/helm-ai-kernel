---
title: Compliance in HELM — Enforcement vs Mapping
---

# Compliance in HELM — Enforcement vs Mapping

Buyers frequently ask: *"You claim compliance for GDPR, HIPAA, SOX, etc. — does HELM actually block non-compliant decisions at runtime, or is this a mapping document?"* This document answers precisely, with code citations.

**TL;DR**: HELM enforces compliance at runtime through two mechanisms: (1) a general-purpose **enforcement engine** that evaluates signed policy bundles against every governed decision, returning PERMIT/DENY/INDETERMINATE, and (2) **framework-specific record-keeping engines** for GDPR/HIPAA/SOX/SEC/MiCA/DORA/FCA that track regulated events, generate audit reports, and feed data into the enforcement engine. The two layers have different guarantees — read the table carefully before citing compliance in a regulatory context.

## Two kinds of compliance surface

| Surface | What it does | Blocks decisions? | Code |
|---------|--------------|-------------------|------|
| **Enforcement engine** | Evaluates policy bundles against each decision; returns PERMIT / DENY / INDETERMINATE / NOT_APPLICABLE | **YES** | [core/pkg/compliance/enforcement/engine.go](../../core/pkg/compliance/enforcement/engine.go) |
| **Framework engines** | Record regulated events (processing activities, PHI access, financial controls, breaches, BAAs, SAR/DAR requests); generate audit reports | **NO** (logging + scorecard only) | [core/pkg/compliance/{gdpr,hipaa,sox,sec,mica,dora,fca}/](../../core/pkg/compliance/) |
| **Signed reference policy bundles** | P1 policy bundles interpreting a framework into concrete CEL/WASM rules; loaded by the enforcement engine | Indirectly — they define what the enforcement engine enforces | [reference_packs/*.v1.json](../../reference_packs/) |
| **Scorecard** | Aggregated compliance posture across frameworks | NO (reporting) | [core/pkg/compliance/scorecard.go](../../core/pkg/compliance/scorecard.go) |

## What each framework package actually does

The seven framework packages are **record-keeping + audit-report engines**, not runtime gates. Their job is to keep a cryptographically-auditable record of the regulated events so that when an auditor or regulator asks "prove you did X," HELM can show a signed receipt of X happening (or of X being denied).

### GDPR — [`core/pkg/compliance/gdpr/`](../../core/pkg/compliance/gdpr/)
| Function | Role |
|----------|------|
| `RegisterProcessingActivity` | Records Article 30 ROPA (record of processing activities) |
| `HandleSubjectRequest` | Records Article 15–22 SAR/erasure/portability requests |
| `GetStatus` | Aggregates DPIA/ROPA/breach counters for scorecard |

**Enforcement path**: the reference_pack `reference_packs/customer_ops.v1.json` and `hipaa_covered_entity.v1.json` load CEL rules that the enforcement engine uses to DENY processing without a lawful basis. The GDPR package itself does not block; it records what happens.

### HIPAA — [`core/pkg/compliance/hipaa/`](../../core/pkg/compliance/hipaa/)
| Function | Role |
|----------|------|
| `RecordPHIAccess` | Each PHI access produces a signed audit record |
| `ReportBreach` | Triggers breach notification workflow |
| `RegisterBAA` | Tracks Business Associate Agreements |
| `GenerateAuditReport` | Period-based §164.312(b) audit logs |

**Enforcement path**: `reference_packs/hipaa_covered_entity.v1.json` denies PHI-class tool calls from principals without a matching BAA registration.

### SOX — [`core/pkg/compliance/sox/`](../../core/pkg/compliance/sox/)
Records Section 302/404/409 IC events. Enforcement via bundle.

### SEC — [`core/pkg/compliance/sec/`](../../core/pkg/compliance/sec/)
Records Rule 17a-4 retention + supervisory events.

### MiCA — [`core/pkg/compliance/mica/`](../../core/pkg/compliance/mica/)
Records issuance + marketing compliance events for crypto assets under EU MiCAR.

### DORA — [`core/pkg/compliance/dora/`](../../core/pkg/compliance/dora/)
Records operational-resilience events and has a dedicated `incident_workflow.go` for incident-response reporting (Art. 17–20).

### FCA — [`core/pkg/compliance/fca/`](../../core/pkg/compliance/fca/)
Records UK FCA handbook obligations.

### EU AI Act — [`core/pkg/compliance/euaiact/`](../../core/pkg/compliance/euaiact/)
Tracks high-risk system obligations. Paired with `reference_packs/eu_ai_act_high_risk.v1.json` for enforcement.

### RegWatch — [`core/pkg/compliance/regwatch/`](../../core/pkg/compliance/regwatch/)
Continuous monitoring layer that tracks regulator guidance updates and flags policy bundles needing refresh.

## The enforcement engine in detail

[`core/pkg/compliance/enforcement/engine.go`](../../core/pkg/compliance/enforcement/engine.go) is the only component in `compliance/` that returns a verdict a caller must respect. It integrates the Sovereign Compliance Oracle (SCO) with the SwarmPDP (policy decision point) and returns `EnforcementResult` containing one of:

```go
const (
    Permit        PolicyResult = "PERMIT"         // Compliant
    Deny          PolicyResult = "DENY"           // Non-compliant
    Indeterminate PolicyResult = "INDETERMINATE"  // Error or unknown
    NotApplicable PolicyResult = "NOT_APPLICABLE" // Rule doesn't apply
)
```

`DENY` is fail-closed: the caller **must** not dispatch the underlying tool call. `INDETERMINATE` is also fail-closed by convention — treat errors as denies.

Wiring:
1. Guardian's `ComplianceChecker` interface (see `guardian.WithComplianceChecker(...)`) accepts an enforcement engine.
2. The enforcement engine is called as part of **§Gate 5 / Threat** of the 6-gate pipeline.
3. Deny verdicts produce signed decisions via `crypto.SignReceipt` and land in the ProofGraph with node type EFFECT blocked.

## Signed reference policy bundles

`reference_packs/` contains 9 bundles. Each is a content-addressed, signed policy document. They are the operational bridge between framework semantics (described in the framework engines) and runtime enforcement:

| Pack | Framework | Purpose |
|------|-----------|---------|
| `customer_ops.v1.json` | GDPR + general | Customer-service use case with ROPA lawful-basis enforcement |
| `eu_ai_act_high_risk.v1.json` | EU AI Act | High-risk-system obligations + human oversight |
| `exec_ops.v1.json` | SOX + SEC | Executive decisions with IC gating |
| `hipaa_covered_entity.v1.json` | HIPAA | Covered entity BAA + minimum necessary |
| `iso_42001.v1.json` | ISO 42001 | AI management system controls |
| `pci_dss_4.v1.json` | PCI DSS 4.0 | Cardholder data scope |
| `procurement.v1.json` | Ops | Vendor-risk gating |
| `recruiting.v1.json` | GDPR + EU AI Act | Recruiting use case |
| `soc2_type2.v1.json` | SOC 2 Type II | Trust services criteria |

## Auditor posture — what HELM gives you, what it does not

### Gives you
- **Machine-verifiable evidence** that regulated events happened: JCS-canonical EvidencePack with SHA-256 manifest, Ed25519-signed receipts per decision, Lamport-ordered ProofGraph for causal reconstruction.
- **Runtime DENY** on configured policy-bundle violations.
- **Audit reports** per framework covering the 7 supported regimes.
- **Scorecard** summarizing posture across frameworks.

### Does NOT give you
- A substitute for legal review: HELM records what happened; your counsel decides what the regulator expects.
- Certification out of the box: a certified HELM deployment still requires organizational controls, staffing, and process outside HELM's scope. HELM is the technical evidence layer.
- Universal coverage: a claim of "HELM is SOC 2 compliant" is only meaningful when paired with a specific tenant deployment that has loaded `soc2_type2.v1.json`, configured the enforcement engine, and operates the non-technical controls.
- Enforcement of controls HELM has no visibility into (e.g., physical security).

## How to verify for a given framework

For any framework F in the supported set:

1. **Check the framework engine is wired** — `guardian.WithComplianceChecker(<F-engine>)`.
2. **Check the reference pack is loaded** — confirm the enforcement engine has `<F>.v1.json` in its active bundle set.
3. **Exercise a known-violating call** — see `core/pkg/compliance/enforcement/engine_test.go` and the framework-specific `*_test.go` for patterns.
4. **Confirm DENY produces a receipt** — the test harness asserts a signed denial receipt lands in the ProofGraph.

## References

- Guardian pipeline: [docs/architecture/guardian-pipeline.md](../architecture/guardian-pipeline.md)
- Tool-execution sandbox scope: [docs/architecture/tool-execution-sandbox.md](../architecture/tool-execution-sandbox.md)
- OWASP Agentic Top 10 coverage (with framework-to-ASI cross-references): [docs/security/owasp-agentic-top10-coverage.md](../security/owasp-agentic-top10-coverage.md)
- Evidence Pack spec v1.0: [protocols/spec/evidence-pack-v1.md](../../protocols/spec/evidence-pack-v1.md)

---

*Part of the Phase 1 packaging gate. Last updated 2026-04-15.*
