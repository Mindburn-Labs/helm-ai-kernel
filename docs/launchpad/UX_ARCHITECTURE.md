---
title: Launchpad UX Architecture
last_reviewed: 2026-05-24
---

# Launchpad UX Architecture

Status: implemented Console direction for the Kernel repo, with hosted
entitlements documented as a future integration contract.

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

The Console renders only:

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

Missing data is shown as `unproven`. The Console does not invent a fallback
catalog, mock launch success, raw secret binding, or proof state.

## Component Roles

- `LaunchpadPage.tsx`: route orchestration and API calls.
- `SimpleLaunchHome.tsx`: normal-user entry surface.
- `LaunchWizard.tsx`: select app, select substrate, setup, preflight, launch,
  and proof.
- `AppCard.tsx`: shared app card for ready, setup-needed, blocked, unsupported,
  and fixture-only gated states.
- `RunTimeline.tsx`: run list, event timeline, escalation notice, and proof.
- `ProofPanel.tsx`: universal receipts / EvidencePack / verify command panel.
- `DeveloperModePanel.tsx`: raw backend payload disclosure.
- `EntitlementGate.tsx`: passive rendering of explicit entitlement decisions.

The Universal Importer panel is part of `LaunchpadPage.tsx` in this pass. It
renders only `/api/v1/launchpad/imports` data and keeps generated AppSpecs
visibly `generated/untrusted` until backend evidence exists.

## Entitlement Boundary

The Kernel repo currently has no production hosted account entitlement layer.
Future Free / Individual / Enterprise differences belong in account/session
contracts and backend action decisions. They must not create duplicate
Launchpad pages, route trees, registries, proof panels, or Kernel semantics.

Tests may include fixture-only entitlement states to preserve the target UX
contract. Runtime code must treat those states as optional backend data.
