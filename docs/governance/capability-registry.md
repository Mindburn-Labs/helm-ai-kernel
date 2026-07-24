# Governed Capability Registry (R1)

**Status:** preview specification. Schemas are merged; guardian enforcement
wiring is follow-up work and is **not** claimed as implemented.
**Origin:** Step AOS alignment workstream (2026-07-24), research:
`research/step-aos-2026-07/STEP-AOS-DEEP-RESEARCH.md`.

## Problem

Agentic OSes (Step AOS, Honor AgenticOS, HarmonyOS 7, openKylin) are
converging on the same action-layer pattern: decompose every system and app
function into **atomic capabilities** that agents discover, compose, and
invoke over MCP / A2A / CLI / unified API. Step AOS calls this the
原子能力引擎 (atomic capability engine) — thousands of units in four
categories (comms, apps, files, system).

That registry is the new control plane. Whoever defines how capabilities are
described, risk-classed, and receipted defines what agents are allowed to do.
Today Step AOS's registry is closed and carries no public risk or effect
metadata; HELM's guardian sees tools but has no shared manifest vocabulary to
decide *against*.

## Design

Every agent-callable capability is described by one
**Governed Capability Manifest**
(`protocols/json-schemas/capability/capability_manifest.v1.json`):

| Field | Purpose |
| --- | --- |
| `capability_id` | Dotted namespaced id (`helm.cap.mcp.gelab.tap`) — the registry key every effect resolves to before dispatch |
| `protocol` + `binding` | Dispatch surface (mcp / a2a / cli / http-api / gui-action / syscall) and concrete reference |
| `effect_class` | Worst-case effect: `read_only`, `write_local`, `write_external`, `network_egress`, `credential_access`, `code_execution`, `financial`, `irreversible` |
| `reversibility` | Reuses `effect_type_definition/v2`: `none` / `compensating_action` / `exact_undo`; drives rollback requirements (see `reversibility-classes.md`) |
| `data_boundary` | `local_only` / `device_boundary` / `org_boundary` / `external` — maps to edge/TEE vs cloud execution constraints |
| `risk_score` | 0–100, feeds guardian thresholds |
| `required_permit_level` | `none` / `single_approval` / `multi_party_permit` (distinct-provider 2-of-2) |
| `rollback.plan_ref` | Required for non-read-only capabilities whose reversibility is not `none` |
| `receipts` | Always required; receipt schema refs per dispatch |
| `memory_access` | Per-domain (user/agent) read/write grants; cross-domain reads default deny (see `memory-governance.md`) |
| `routing.min_model_tier` | Minimum model tier allowed to plan/invoke (see `model-routing-policy.md`) |

## Decision flow (target)

```text
Agent intent
  → resolve effect to capability_id in registry
  → load manifest (hash-pinned revision)
  → guardian evaluates: effect_class, reversibility, data_boundary,
    risk_score, permit level, capability token (if required)
  → ALLOW (receipt + optional rollback plan binding)
    / DENY (fail-closed receipt)
    / ESCALATE (permit flow, quarantine record)
  → dispatch via protocol binding
  → execution receipt pairs with decision receipt
```

Unknown capability id = **fail closed** (same posture as unknown MCP tools
today: quarantine + escalate).

## Registry service (target shape)

- Content-addressed manifest store (`sha256` of canonical manifest = revision id).
- Certification transition: `draft → certified → deprecated`, recorded as receipts.
- Read API for guardian; write API behind multi-party permit.
- Import adapters: MCP server tool listings, A2A agent cards, SKILL.md
  frontmatter (see `skills-certification-profile-v1.md`), OpenAPI operations.

## Relationship to existing surfaces

- `connectors/` certification (`/helm-connector-cert`) becomes the pipeline
  that produces certified manifests.
- `effect_type_definition/v2` remains the per-effect vocabulary; the manifest
  is the per-capability registry-level view.
- Boundary Enforcement Profile stays the OS-enforcement compiler; the
  capability registry governs the agent-dispatch plane above it.

## Non-goals

- Not a model router (see `model-routing-policy.md` for the policy seam only).
- Not an app store; no distribution, billing, or discovery UX in this layer.
