---
title: Mindburn Account Entitlements Integration Contract
last_reviewed: 2026-05-23
---

# Mindburn Account Entitlements Integration Contract

<!-- quantum_posture: entitlement adapter docs reference JWKS configuration only; this contract adds no cryptographic control. -->

Status: integration contract plus optional Kernel adapter. `helm-ai-enterprise`
Control Plane owns hosted Free / Developer / Team / Scale / Enterprise account
decisions.
`helm-ai-kernel` remains self-hostable and does not infer account tier when the
hosted adapter is not configured.

## Current Repo-Backed Scope

- External clients use existing Launchpad APIs for apps, substrates, matrix,
  plan, runs, sandbox, MCP reviews, secrets, receipts, EvidencePack export,
  teardown, repair, and delete.
- OpenClaw, Hermes, OpenCode, and Kilo Code support comes from
  `registry/launchpad`, `policies/launchpad`, and `docs/LAUNCHPAD.md`.
- Proof semantics remain universal: LaunchPlan hashes, receipts, EvidencePack
  refs, offline verify commands, sandbox grants, and MCP state are not premium
  UI features.

## Hosted Flow

```text
Mindburn hosted shell
  -> login
  -> account session
  -> entitlement decision
  -> single Kernel Launchpad shell
  -> existing Launchpad API and Kernel boundary
  -> receipts / EvidencePack / teardown
```

The hosted shell supplies account/session state through Control Plane account
routes. It must not implement custom app launch, custom proof display, or
tier-specific Kernel semantics.

## Implemented Control Plane Routes

`helm-ai-enterprise` exposes the hosted account authority:

```text
GET  /api/v1/account/session
GET  /api/v1/account/entitlements
POST /api/v1/account/decisions
```

Canonical hosted plans are:

```text
free
developer
team
scale
enterprise
```

Hosted Control Plane may normalize legacy billing names internally, but Kernel
account session and entitlement responses expose only canonical `plan_id`
values from this list. Historical `individual`, `basic`, and `pro` values are
not valid public Kernel SDK plan IDs.

This does not rename `PackChannelIndividual` in `PackManifestV2`: that is a
legacy add-on manifest channel retained for signed-manifest compatibility, not
an account plan ID.

The decision endpoint returns action-level access state and must be called
before mutating Launchpad side effects when hosted gating is enabled.

## Session Contract

Future hosted integration should expose an authenticated session payload with:

```json
{
  "principal_id": "user_123",
  "tenant_id": "tenant_abc",
  "account_id": "acct_abc",
  "plan_id": "developer",
  "source": "mindburn-hosted",
  "expires_at": "2026-05-22T23:00:00Z"
}
```

Standalone clients may continue to use existing tenant/admin headers. That
local identity is not equivalent to a hosted billing plan unless a
real entitlement source provides it.

## Kernel Adapter Configuration

Kernel hosted entitlement integration is disabled by default. Configure it only
when a hosted Control Plane account authority is available:

```bash
HELM_ACCOUNT_ENTITLEMENTS_URL=https://helm.mindburn.org
HELM_ACCOUNT_JWKS_URL=https://helm.mindburn.org/.well-known/jwks.json
HELM_ACCOUNT_ISSUER=https://helm.mindburn.org
HELM_ACCOUNT_AUDIENCE=helm-ai-kernel
HELM_ACCOUNT_REQUIRED=false
```

When disabled, Kernel returns no entitlement fields and preserves existing
self-hosted behavior. When enabled, Kernel forwards the hosted session credential
to the Control Plane decision endpoint. When `HELM_ACCOUNT_REQUIRED=true`,
unavailable or invalid hosted decisions fail closed before mutating Launchpad
side effects.

## Entitlement Contract

Entitlements are action decisions, not alternate products:

```json
{
  "plan": "free",
  "limits": {
    "monthly_launches": 10,
    "concurrent_runs": 1,
    "retention_days": 7,
    "max_cloud_targets": 0,
    "evidence_export_mb": 25
  },
  "capabilities": {
    "local_launch": true,
    "demo_launch": true,
    "cloud_launch": true,
    "custom_policy": false,
    "bring_own_secrets": true,
    "evidence_export": true,
    "offline_verify": true,
    "team_admin": false,
    "sso": false,
    "legal_hold": false,
    "certified_connectors": false,
    "enterprise_retention": false
  }
}
```

The hosted service should answer the question:

```text
Can this principal perform this action on this AppSpec/substrate/run now?
```

It should not ask:

```text
Which tier-specific Launchpad should the UI render?
```

Decision requests include principal, tenant, workspace, action, app, substrate,
target, current usage, and optional run ID. Decision responses include:

```json
{
  "allowed": false,
  "user_state": "upgrade_required",
  "required_capability": "cloud_launch",
  "reason_code": "ENTITLEMENT_UPGRADE_REQUIRED",
  "reason": "Capability is not enabled for this hosted account.",
  "upgrade_reason": "Upgrade your hosted HELM plan to use this capability.",
  "limit": 0,
  "used": 0,
  "remaining": 0,
  "decision_ref": "ent_abc123",
  "source": "controlplane.account.decisions",
  "expires_at": "2026-05-23T12:00:00Z"
}
```

Proof viewing and teardown are universal. Launch/create, evidence export,
cloud launch, custom policy, and bring-your-own-secret actions can be gated.

## Additive Launchpad Fields

When entitlement data exists, backend responses may add fields like:

```json
{
  "app_id": "hermes",
  "user_state": "upgrade_required",
  "required_capability": "cloud_launch",
  "upgrade_reason": "Cloud launches require a paid hosted plan.",
  "action_states": {
    "preflight": { "action": "preflight", "allowed": true },
    "launch": {
      "action": "launch",
      "allowed": false,
      "required_capability": "cloud_launch",
      "upgrade_reason": "Cloud launches require a paid hosted plan."
    }
  }
}
```

These fields are optional and additive. In production, clients may render them
only when the backend returns them. Tests may use fixture-only entitlement
states, but fixture states must be visibly labeled and must not become runtime
fallback data.

## Non-Negotiables

- One Launchpad UI shell.
- One app catalog.
- One Launchpad route family.
- One AppSpec / LaunchPlan / Receipt / EvidencePack model.
- No Free, Developer, Team, Scale, or Enterprise Kernel forks.
- No UI-only launchability, verdict, proof, secret, sandbox, MCP, or teardown
  claims.
