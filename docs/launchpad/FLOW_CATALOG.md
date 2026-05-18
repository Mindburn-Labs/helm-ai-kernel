# HELM Launchpad Flow Catalog

HELM Launchpad is the OSS local-container app launcher for AI agents. Launchpad starts apps; HELM governs execution.

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

[KEEP] The fail-closed Launchpad registry/session/receipt/runtime base exists.

[REFACTOR] The CPI/PEP/boundary path still needs deeper action-by-action authority binding.

[REWRITE] OpenClaw and Hermes live conformance must run real containers before promotion.

[DEFER] DigitalOcean and Hetzner stay dry-run by default.
