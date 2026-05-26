---
title: Mindburn Account Entitlements Integration Contract
last_reviewed: 2026-05-22
---

# Mindburn Account Entitlements Integration Contract

Status: target integration contract. `helm-ai-kernel` does not currently ship a
production Free / Individual / Enterprise entitlement service or Mindburn hosted
login flow. Kernel Launchpad must not infer account tier in API state.

## Current Repo-Backed Scope

- External clients use existing Launchpad APIs for apps, substrates, matrix,
  plan, runs, sandbox, MCP reviews, secrets, receipts, EvidencePack export,
  teardown, repair, and delete.
- OpenClaw, Hermes, OpenCode, and Kilo Code support comes from
  `registry/launchpad`, `policies/launchpad`, and `docs/LAUNCHPAD.md`.
- Proof semantics remain universal: LaunchPlan hashes, receipts, EvidencePack
  refs, offline verify commands, sandbox grants, and MCP state are not premium
  UI features.

## Target Hosted Flow

```text
Mindburn hosted shell
  -> login
  -> account session
  -> entitlement decision
  -> single Kernel Launchpad shell
  -> existing Launchpad API and Kernel boundary
  -> receipts / EvidencePack / teardown
```

The hosted shell may supply account state. It must not implement custom app
launch, custom proof display, or tier-specific Kernel semantics.

## Session Contract

Future hosted integration should expose an authenticated session payload with:

```json
{
  "principal_id": "user_123",
  "tenant_id": "tenant_abc",
  "account_id": "acct_abc",
  "plan": "individual",
  "source": "mindburn-hosted",
  "expires_at": "2026-05-22T23:00:00Z"
}
```

Standalone clients may continue to use existing tenant/admin headers. That
local identity is not equivalent to a hosted billing plan unless a
real entitlement source provides it.

## Entitlement Contract

Entitlements are action decisions, not alternate products:

```json
{
  "plan": "free",
  "limits": {
    "monthly_launches": 10,
    "concurrent_runs": 1,
    "retention_days": 7,
    "max_cloud_targets": 1
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
- No Free, Individual, or Enterprise Kernel forks.
- No UI-only launchability, verdict, proof, secret, sandbox, MCP, or teardown
  claims.
