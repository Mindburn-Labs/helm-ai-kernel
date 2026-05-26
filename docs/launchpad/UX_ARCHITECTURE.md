---
title: Launchpad External Client Contract
last_reviewed: 2026-05-24
---

# Launchpad External Client Contract

Status: API contract for a standalone Console or other external client. The
Kernel repo owns the backend facts and proof states, not browser components.

## Product Shape

Launchpad is one product surface:

```text
App catalog -> preflight -> setup secrets -> launch safely -> run timeline -> proof -> teardown
```

The same surface now includes a Universal Importer entry point:

```text
Paste repo URL -> inspect source -> capability graph -> generated target plans -> import preflight -> evidence-gated promotion
```

Simple Mode and Developer Mode are depth controls on the same backend facts.
They are not Free / Individual / Enterprise variants.

## Source Of Truth

External clients render only:

- app and substrate registry fields
- compatibility matrix cells
- LaunchPlan verdicts and hashes
- required secret grant status
- MCP threat-review state
- sandbox grant facts
- run events and gates
- receipt refs
- EvidencePack refs and offline verify commands
- teardown state
- SourceSnapshot, CapabilityGraph, LaunchRecipe, target plans, generated
  AppSpec candidates, and import preflight records
- explicit backend-returned or test-fixture entitlement fields

Missing data is shown as `unproven`. External clients do not invent a fallback
catalog, mock launch success, raw secret binding, or proof state.

## Client Responsibilities

External clients may compose app catalog, setup, run timeline, proof, and
import flows in any framework, but must treat `/api/v1/launchpad/*`,
`/api/v1/console/*`, `/api/v1/agent-ui/*`, receipts, and EvidencePack refs as
the source of truth. Generated AppSpecs remain `generated/untrusted` until
backend evidence exists.

## Entitlement Boundary

The Kernel repo currently has no production hosted account entitlement layer.
Future Free / Individual / Enterprise differences belong in account/session
contracts and backend action decisions. They must not create duplicate
Launchpad pages, route trees, registries, proof panels, or Kernel semantics.

Tests may include fixture-only entitlement states to preserve the target UX
contract. Runtime code must treat those states as optional backend data.
