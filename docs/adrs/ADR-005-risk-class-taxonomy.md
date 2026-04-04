# ADR-005: R0-R3 Action Risk Class Taxonomy

**Status:** Accepted
**Date:** 2026-04-04

## Context

The existing HELM system uses E0-E4 effect risk classes (from `contracts.EffectRiskClass()`) to classify individual effect types. Executive automation requires a higher-level risk classification for **action proposals** -- what a virtual employee is trying to accomplish, not just what tool it will call.

## Decision

Introduce **R0-R3 action risk classes** layered on top of E0-E4:

| Class | Meaning | Governance Rule |
|---|---|---|
| R0 | Read-only / reversible internal draft | Auto-approved, logged only |
| R1 | Internal write / low-risk collaboration | Auto-approved, inbox-visible |
| R2 | External communication / candidate/customer-visible | Inbox-visible, manager can inspect and override |
| R3 | Financial, legal, production, or irreversible effect | Full approval ceremony required |

### Mapping to E-classes

| R-class | Default E-class | Rationale |
|---|---|---|
| R0 | E0 | Read-only, informational |
| R1 | E1 | Low risk, reversible |
| R2 | E2 | Medium risk, external-facing |
| R3 | E4 | Critical, irreversible |
| Unknown | E3 | Fail-closed |

### Key distinction

- **E-classes** classify **effect types** (what a tool does). Defined in `contracts/effect_types.go`.
- **R-classes** classify **action proposals** (what a virtual employee is trying to accomplish). Defined in `actiongraph/risk_class.go`.
- An R2 proposal may contain R1 effects (e.g., sending an internal email), but the overall action is customer-visible, hence R2.

### Additional rules

- R2+ requires inbox visibility (manager sees it).
- R3 requires approval ceremony (manager must explicitly approve).
- Analog-world actions (phone calls, physical meetings) escalate by default.

## Consequences

- The Guardian continues to use E-classes internally; no changes to guardian.go.
- R-classes are used by `actiongraph/` and `actioninbox/` layers.
- `RiskClassToEffectClass()` provides the bridge function.
- Unknown effect types default to E3 (fail-closed), consistent with existing `EffectRiskClass()` behavior.
