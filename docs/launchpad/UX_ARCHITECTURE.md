---
title: Launchpad External Client Contract
last_reviewed: 2026-05-24
---

# Launchpad External Client Contract

Status: implemented Console direction for the Kernel repo, with hosted
entitlements represented as optional backend-returned action state. The hosted
account authority lives in `helm-ai-enterprise`; Kernel remains self-hostable
without account configuration.

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
They are not Free / Developer / Team / Scale / Enterprise variants.

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

Kernel does not create plan state by itself. When
`HELM_ACCOUNT_ENTITLEMENTS_URL` is unset, the Console sees the same Launchpad
payloads as before. When the adapter is configured, Kernel may attach additive
fields:

- `user_state`
- `required_capability`
- `upgrade_reason`
- `entitlement_decision`
- `action_states`

Mutating routes deny before LaunchKit side effects when the hosted decision
returns `allowed=false`. Proof viewing and teardown stay on the same universal
surface and are not paywalled.

Tests may include fixture-only entitlement states to preserve the target UX
contract. Runtime code must treat those states as optional backend data.
