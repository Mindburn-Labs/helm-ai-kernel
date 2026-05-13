---
title: HELM AI Kernel CLI Reference
last_reviewed: 2026-05-05
---

# HELM AI Kernel CLI Reference

The `helm-ai-kernel` binary is wired in [`core/cmd/helm-ai-kernel`](../../core/cmd/helm-ai-kernel). Command registration is centralized in [`registry.go`](../../core/cmd/helm-ai-kernel/registry.go), with startup handling in [`main.go`](../../core/cmd/helm-ai-kernel/main.go) and `helm-ai-kernel serve` flag parsing in [`server_cmd.go`](../../core/cmd/helm-ai-kernel/server_cmd.go).

## Audience

Use this page if you run the HELM AI Kernel binary, copy CLI snippets into automation, or update command docs after changing `core/cmd/helm-ai-kernel`.

## Outcome

After this page you should know the supported top-level command families, the source file that owns each command, the flag contracts that public docs may claim, and the tests that must pass after command changes.

## Source Truth

This page is generated from the active CLI implementation and must stay aligned with [`core/cmd/helm-ai-kernel`](../../core/cmd/helm-ai-kernel), [`core/cmd/README.md`](../../core/cmd/README.md), the command tests in [`core/cmd/helm-ai-kernel`](../../core/cmd/helm-ai-kernel), and the public manifest row for `helm-ai-kernel/reference/cli`.

## Runtime Map

```mermaid
flowchart LR
  User["operator or client"] --> CLI["helm-ai-kernel command"]
  CLI --> Registry["command registry"]
  Registry --> Server["serve / server"]
  Registry --> Proxy["proxy"]
  Registry --> Boundary["boundary / mcp / sandbox / authz"]
  Registry --> Evidence["receipts / evidence / verify"]
  Server --> API["HTTP API"]
  Proxy --> Upstream["OpenAI-compatible upstream"]
  Boundary --> State["boundary surface registry"]
  Evidence --> Pack["EvidencePack or receipt stream"]
```

## Primary Commands

| Command | Purpose | Source truth |
| --- | --- | --- |
| `helm-ai-kernel serve` | Start the local execution boundary from a policy file. | [`server_cmd.go`](../../core/cmd/helm-ai-kernel/server_cmd.go), [`serve_policy.go`](../../core/cmd/helm-ai-kernel/serve_policy.go) |
| `helm-ai-kernel server` | Start the default Guardian API and proxy services. | [`main.go`](../../core/cmd/helm-ai-kernel/main.go), [`subsystems.go`](../../core/cmd/helm-ai-kernel/subsystems.go) |
| `helm-ai-kernel proxy` | Run the OpenAI-compatible governance proxy. | [`proxy_cmd.go`](../../core/cmd/helm-ai-kernel/proxy_cmd.go) |
| `helm-ai-kernel receipts tail` | Tail durable receipt events for a specific agent. | [`receipts_cmd.go`](../../core/cmd/helm-ai-kernel/receipts_cmd.go), [`receipt_routes.go`](../../core/cmd/helm-ai-kernel/receipt_routes.go) |
| `helm-ai-kernel evidence` | Export evidence envelopes over native EvidencePacks. | [`evidence_cmd.go`](../../core/cmd/helm-ai-kernel/evidence_cmd.go), [`contract_routes.go`](../../core/cmd/helm-ai-kernel/contract_routes.go) |
| `helm-ai-kernel export` | Export an EvidencePack from local evidence material. | [`export_cmd.go`](../../core/cmd/helm-ai-kernel/export_cmd.go), [`export_pack.go`](../../core/cmd/helm-ai-kernel/export_pack.go) |
| `helm-ai-kernel verify` | Verify an EvidencePack directory or archive offline, with optional online proof checks. | [`verify_cmd.go`](../../core/cmd/helm-ai-kernel/verify_cmd.go), [`core/pkg/verifier`](../../core/pkg/verifier) |
| `helm-ai-kernel bundle` | List, inspect, verify, or build policy bundles. | [`bundle_cmd.go`](../../core/cmd/helm-ai-kernel/bundle_cmd.go), [`core/pkg/policybundles`](../../core/pkg/policybundles) |
| `helm-ai-kernel conform` | Run conformance gates and list negative boundary vectors. | [`conform.go`](../../core/cmd/helm-ai-kernel/conform.go), [`core/pkg/conformance`](../../core/pkg/conformance) |
| `helm-ai-kernel mcp` | Serve, package, scan, quarantine, approve, and authorize MCP surfaces. | [`mcp_cmd.go`](../../core/cmd/helm-ai-kernel/mcp_cmd.go), [`mcp_boundary_cmd.go`](../../core/cmd/helm-ai-kernel/mcp_boundary_cmd.go), [`mcp_runtime.go`](../../core/cmd/helm-ai-kernel/mcp_runtime.go) |
| `helm-ai-kernel boundary` | Inspect execution-boundary status, capabilities, records, verification, and checkpoints. | [`boundary_surface_cmd.go`](../../core/cmd/helm-ai-kernel/boundary_surface_cmd.go), [`core/pkg/boundary`](../../core/pkg/boundary) |
| `helm-ai-kernel identity` | Inspect HELM AI Kernel agent identities. | [`boundary_surface_cmd.go`](../../core/cmd/helm-ai-kernel/boundary_surface_cmd.go), [`core/pkg/identity`](../../core/pkg/identity) |
| `helm-ai-kernel sandbox` | Run governed sandbox execution and inspect sandbox grants. | [`sandbox_cmd.go`](../../core/cmd/helm-ai-kernel/sandbox_cmd.go), [`sandbox_inspect_cmd.go`](../../core/cmd/helm-ai-kernel/sandbox_inspect_cmd.go) |
| `helm-ai-kernel authz`, `helm-ai-kernel approvals`, `helm-ai-kernel budget` | Inspect ReBAC snapshots, approval ceremonies, and budget ceilings. | [`boundary_surface_cmd.go`](../../core/cmd/helm-ai-kernel/boundary_surface_cmd.go), [`core/pkg/contracts`](../../core/pkg/contracts) |
| `helm-ai-kernel telemetry`, `helm-ai-kernel coexistence`, `helm-ai-kernel integrate` | Emit non-authoritative telemetry, coexistence, and pre-dispatch integration scaffolds. | [`boundary_surface_cmd.go`](../../core/cmd/helm-ai-kernel/boundary_surface_cmd.go) |
| `helm-ai-kernel policy`, `helm-ai-kernel plan`, `helm-ai-kernel pack` | Work with policy tests, execution plans, and governed self-extension packs. | [`policy_cmd.go`](../../core/cmd/helm-ai-kernel/policy_cmd.go), [`plan_cmd.go`](../../core/cmd/helm-ai-kernel/plan_cmd.go), [`pack_cmd.go`](../../core/cmd/helm-ai-kernel/pack_cmd.go) |
| `helm-ai-kernel test` | Run local HELM smoke checks exposed by the CLI. | [`test_cmd.go`](../../core/cmd/helm-ai-kernel/test_cmd.go) |
| `helm-ai-kernel scaffold`, `helm-ai-kernel dev` | Create a local governance scaffold and start HELM in development mode. | [`init_cmd.go`](../../core/cmd/helm-ai-kernel/init_cmd.go) |
| `helm-ai-kernel pack coverage` | Show governed self-extension pack coverage statistics. | [`pack_cmd.go`](../../core/cmd/helm-ai-kernel/pack_cmd.go) |
| `helm-ai-kernel doctor`, `helm-ai-kernel init`, `helm-ai-kernel onboard`, `helm-ai-kernel demo` | Initialize, diagnose, and run local demonstration flows. | [`doctor_cmd.go`](../../core/cmd/helm-ai-kernel/doctor_cmd.go), [`doctor_init_trust.go`](../../core/cmd/helm-ai-kernel/doctor_init_trust.go), [`onboard_cmd.go`](../../core/cmd/helm-ai-kernel/onboard_cmd.go), [`demo_cmd.go`](../../core/cmd/helm-ai-kernel/demo_cmd.go) |
| `helm-ai-kernel replay`, `helm-ai-kernel report`, `helm-ai-kernel certify`, `helm-ai-kernel rollup` | Replay evidence, report compliance, certify packs, and build receipt rollups. | [`replay_cmd.go`](../../core/cmd/helm-ai-kernel/replay_cmd.go), [`report_cmd.go`](../../core/cmd/helm-ai-kernel/report_cmd.go), [`certify_cmd.go`](../../core/cmd/helm-ai-kernel/certify_cmd.go), [`rollup_cmd.go`](../../core/cmd/helm-ai-kernel/rollup_cmd.go) |
| `helm-ai-kernel freeze`, `helm-ai-kernel unfreeze`, `helm-ai-kernel incident`, `helm-ai-kernel brief`, `helm-ai-kernel risk-summary` | Operate local safety, incident, brief, and risk surfaces. | [`freeze_cmd.go`](../../core/cmd/helm-ai-kernel/freeze_cmd.go), [`incident_cmd.go`](../../core/cmd/helm-ai-kernel/incident_cmd.go), [`risk_cmd.go`](../../core/cmd/helm-ai-kernel/risk_cmd.go) |
| `helm-ai-kernel trust`, `helm-ai-kernel threat`, `helm-ai-kernel shadow`, `helm-ai-kernel did`, `helm-ai-kernel tee`, `helm-ai-kernel local` | Inspect trust roots, threats, shadow-AI patterns, identifiers, TEE attestations, and local provider profiles. | [`trust_cmd.go`](../../core/cmd/helm-ai-kernel/trust_cmd.go), [`threat_cmd.go`](../../core/cmd/helm-ai-kernel/threat_cmd.go), [`shadow_cmd.go`](../../core/cmd/helm-ai-kernel/shadow_cmd.go), [`did_cmd.go`](../../core/cmd/helm-ai-kernel/did_cmd.go), [`tee_cmd.go`](../../core/cmd/helm-ai-kernel/tee_cmd.go), [`local_cmd.go`](../../core/cmd/helm-ai-kernel/local_cmd.go) |
| `helm-ai-kernel health`, `helm-ai-kernel version`, `helm-ai-kernel help` | Global utility commands for local health checks, version reporting, and usage output. | [`main.go`](../../core/cmd/helm-ai-kernel/main.go), [`registry.go`](../../core/cmd/helm-ai-kernel/registry.go) |

Auxiliary binaries under `core/cmd/bootstrap`, `core/cmd/channel_gateway`, `core/cmd/pack_verify`, `core/cmd/skill_lint`, and `core/cmd/skill_pack` are source-owned helpers. They are not top-level `helm-ai-kernel` subcommands unless wired through `core/cmd/helm-ai-kernel`.

This table documents registered top-level `helm-ai-kernel` command families and global utility commands. Aliases are documented in source and should be exposed here only when public examples rely on them.

## Key Flag Contracts

| Command | Contract |
| --- | --- |
| `helm-ai-kernel serve --policy <path>` | `--policy` is required. Optional flags are `--addr`, `--port`, `--data-dir`, `--console`, `--console-dir`, and `--json`. If the policy does not override bind or port, `serve` uses `127.0.0.1:7714`. |
| `helm-ai-kernel server` | Starts without `--policy` and defaults to `127.0.0.1:8080` unless flags, env, or config override it. `HELM_BIND_ADDR` overrides the bind address when no explicit flag is set. `HELM_PORT` overrides the API port when no explicit flag is set. The separate health server uses `HELM_HEALTH_PORT` and defaults to `8081`. |
| `helm-ai-kernel proxy` | Defaults to `--upstream https://api.openai.com/v1`, `--port 9090`, and `--receipts-dir ./helm-receipts`. `--websocket` is explicitly unsupported in the OSS proxy runtime. |
| `helm-ai-kernel health` | Checks `http://localhost:$HELM_HEALTH_PORT/healthz`; if `HELM_HEALTH_PORT` is unset, it checks `http://localhost:8081/healthz`. |
| `helm-ai-kernel receipts tail` | Requires `--agent <id>`. `--server` defaults from `HELM_URL` or `http://127.0.0.1:7714`. |
| `helm-ai-kernel bundle build` | Takes the policy source as the positional argument: `helm-ai-kernel bundle build [--language=cel|rego|cedar] [--entities=path] <source>`. There is no `--policy` flag for this subcommand. |
| `helm-ai-kernel bundle verify` | Requires `--file <bundle.yaml>` and `--hash <expected-hash>`. |
| `helm-ai-kernel verify` | Accepts a positional EvidencePack path or `--bundle`. `--online` only adds public proof-ledger verification after offline checks pass. |
| `helm-ai-kernel boundary` | Uses `status`, `capabilities`, `records`, `get`, `verify`, and `checkpoint` subcommands. |

## Boundary And API References

- [HTTP API Reference](http-api.md) covers the route registry, auth classes, OpenAPI contract, and local API behavior.
- [Execution Boundary Reference](execution-boundary.md) covers boundary records, checkpoints, fail-closed cases, and native evidence authority.

## Validation

Run CLI-focused validation after changing command flags or public examples:

```bash
cd core
go test ./cmd/helm-ai-kernel -count=1
```

Then run the documentation gates from the repository root:

```bash
make docs-coverage
make docs-truth
```

## Troubleshooting

| Symptom | First check |
| --- | --- |
| A command snippet fails with an unknown flag | Compare the snippet with `core/cmd/helm-ai-kernel/*_cmd.go`; for example, `helm-ai-kernel bundle build` takes the policy source positionally, not through `--policy`. |
| A helper binary appears in public docs as a `helm-ai-kernel` subcommand | Keep helper binaries source-owned unless they are registered in `core/cmd/helm-ai-kernel/registry.go`. |
| CLI docs and tests disagree | Update the source command, the command test, and this reference in the same change. |
