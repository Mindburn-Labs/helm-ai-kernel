---
title: HELM Launchpad Flow Catalog
last_reviewed: 2026-05-20
---

# HELM Launchpad Flow Catalog

HELM Launchpad is the OSS local-container app launcher for AI agents. Launchpad starts apps; HELM governs execution.

## Audience

This page is for developers, operators, and reviewers validating the OSS
Launchpad matrix, plan, local-container launch, repair, and teardown flows.

## Outcome

You should leave with the supported Launchpad command path and the receipts,
EvidencePack, sandbox, and policy checks required before an app is considered
available.

## Source Truth

- CLI launch command: `core/cmd/helm-ai-kernel/launch_cmd.go`
- Launchpad runtime: `core/pkg/launchpad/`
- App registry: `registry/launchpad/apps/`
- Substrate registry: `registry/launchpad/substrates/`
- App policies: `policies/launchpad/apps/`
- Release truth: `docs/launchpad/v1_report.json`
- Clean-install truth: `docs/launchpad/clean_install_report.json`

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Context Plane"]
        matrix["matrix"]
        plan["plan"]
        launch["local-container launch"]
        repair["repair plan"]
        teardown["cascade teardown"]
    end

    subgraph Ledger["4. Tamper-Evident Ledger Plane"]
        receipts["signed receipts"]
        evidence["EvidencePack export"]
        verify["offline verify"]
    end

    %% Operational Flow Edges
    matrix --> plan
    plan --> launch
    launch --> receipts
    receipts --> evidence
    evidence --> verify
    launch --> repair
    launch --> teardown

    %% Premium Styling Rules
    style receipts fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
    style evidence fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
    style verify fill:#2f855a,stroke:#276749,stroke-width:2px,color:#fff
```


## Matrix

`helm-ai-kernel launch matrix --json`

Loads AppSpecs, SubstrateSpecs, policy packs, and conformance metadata. No app is `AVAILABLE` without license, artifact, policy, sandbox, healthcheck, e2e, receipts, teardown, and offline EvidencePack proof.

## Plan

`helm-ai-kernel launch plan <app> <substrate> --json`

Compiles a LaunchPlan with app/substrate/policy/sandbox hashes, required secrets, network allowlist, filesystem mounts, MCP policy, budgets, action IR, CPI output, verdict, state, teardown plan, and evidence requirements.

## Launch Local Container

`helm-ai-kernel launch openclaw local-container --headless --output json`

Required path:

1. Resolve AppSpec and SubstrateSpec.
2. Verify signed artifact evidence and conformance metadata.
3. Compile policy and action IR.
4. Pass CPI/PEP/boundary checks.
5. Run sandbox preflight.
6. Bind MCP as quarantined.
7. Install immutable artifact.
8. Start local-container with deny-by-default filesystem and network.
9. Project scoped secrets.
10. Route OpenRouter egress through launch-owned proxy.
11. Run healthcheck.
12. Emit receipts and EvidencePack.

## Repair

`helm-ai-kernel launch repair <launch_id>`

Produces a deterministic repair plan for missing secrets, healthcheck failures, MCP auth expiry, sandbox failure, policy denial, dirty install attempts, port/proxy collisions, and ambiguous cloud state. Repair side effects still require CPI/PEP.

## Teardown

`helm-ai-kernel launch delete <launch_id> --cascade`

Stops containers and proxy, revokes scoped secrets, revokes sandbox grants, quarantines or revokes MCP registrations, reconciles remote resources when applicable, emits teardown receipt, and updates the final EvidencePack.

## Current Truth

[KEEP] OpenClaw, Hermes, OpenCode, and Kilo Code are `oss_supported` from
workflow `26198407296`, with signed artifacts, live local-container e2e,
teardown receipts, and offline EvidencePack verification.

[REFACTOR] The CPI/PEP/boundary path still needs deeper action-by-action authority binding.

[REBUILD] Clean install GA is not complete until `scripts/launch/clean_install_gate.sh`
passes against `v0.5.8` on both the macOS CI runner and a separate developer Mac.

Deferred: DigitalOcean and Hetzner stay dry-run by default.

## Troubleshooting

| Condition | Response |
| --- | --- |
| App is not `AVAILABLE` | Check license, artifact, policy, sandbox, healthcheck, e2e, receipt, teardown, and EvidencePack proof. |
| Launch is denied | Treat the policy verdict as final and inspect the action IR and policy pack hashes. |
| Repair proposes side effects | Re-run CPI/PEP checks before accepting any repair action. |
| Teardown is incomplete | Keep the launch non-promotable until container, proxy, secret, MCP, and evidence state reconcile. |
