# Risk-Tiered Model Routing Policy (R6)

**Status:** preview specification (doc-led; manifest hook merged in
`capability_manifest.v1.json → routing.min_model_tier`).
**Origin:** Step AOS Fast/Deep/Hybrid path edge-cloud cascade, re-expressed
as guardian policy where routing decisions are receipted.

## Problem

Step AOS routes by latency and cost: edge model for fast tasks, cloud
flagship for deep reasoning. That optimizes UX, not safety. A governed
system must route by **risk first**: the model tier is part of the trust
chain, because the planning model decides what gets attempted and how
arguments are shaped.

## Tiers

| Tier | Class of model | Default scope |
| --- | --- | --- |
| `fast_edge` | Small on-device models (e.g. Step Edge class, 4B-class GUI models) | `read_only` and `write_local` capabilities with `data_boundary: local_only`; never `financial`, `credential_access`, or `irreversible` |
| `standard` | Mid cloud models (Flash class) | Up to `write_external` with receipts; escalation boundary per policy |
| `deep_reasoning` | Frontier cloud models | Required for planning that composes ≥3 capabilities, touches `org_boundary`+ data, or requests permits |

## Rules

1. **Risk dominates latency.** A fast-path-eligible intent loses fast-path
   eligibility the moment its resolved capability set includes anything above
   the tier ceiling. Escalation of model tier is always allowed; silent
   downgrade is a policy violation.
2. **Routing is receipted.** Every decision receipt records `model_tier`,
   model identity, and (where available) model version/digest — closing the
   loop between *which brain planned* and *what was allowed*.
3. **Privacy ceiling couples to data boundary.** Intents whose resolved data
   is `local_only`/`device_boundary` must not be planned by models that
   transmit context externally, regardless of tier.
4. **Hybrid paths keep the edge in the loop.** Cloud-planned steps that
   execute on-device re-enter the boundary at the edge; the edge guardian's
   decision is authoritative for dispatch.
5. **Policy-adherence input.** Model choice should prefer models with
   measured multi-turn policy adherence (e.g. ClawEval-class adversarial
   benchmarks) for any tier that can reach non-read-only effects; see
   `reference_packs/adversarial-policy-v1/`.

## Non-goals

The guardian does not implement a model router; it constrains and records
routing decisions made by the orchestrator above it.
